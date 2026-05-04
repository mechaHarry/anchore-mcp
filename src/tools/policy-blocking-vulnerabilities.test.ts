import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ResolvedAnchoreConnection } from "../config/connection.js";
import * as safeLog from "../logging/safe-log.js";
import {
  POLICY_BLOCKING_VULNS_REPORT_VERSION,
  runPolicyBlockingVulnerabilities,
} from "./policy-blocking-vulnerabilities.js";

function testConnection(): ResolvedAnchoreConnection {
  return {
    baseUrl: "https://anchore.example.com",
    username: "_api_key",
    password: "test-token",
    apiVersion: "v2",
  };
}

function textPayload(result: Awaited<ReturnType<typeof runPolicyBlockingVulnerabilities>>): string {
  return result.content?.[0]?.type === "text" ? result.content[0].text : "";
}

function parsedToolPayload(result: Awaited<ReturnType<typeof runPolicyBlockingVulnerabilities>>): {
  context: { action: string };
  anchore: Record<string, unknown>;
} {
  return JSON.parse(textPayload(result)) as {
    context: { action: string };
    anchore: Record<string, unknown>;
  };
}

beforeEach(() => {
  vi.spyOn(safeLog, "logStderrLine").mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("runPolicyBlockingVulnerabilities", () => {
  it("returns already_green success without fetching vulnerabilities", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ status: "pass" }), { status: 200 }),
    );

    const result = await runPolicyBlockingVulnerabilities(
      { image_digest: "sha256:green" },
      { connection: testConnection(), fetch: fetchMock },
    );

    expect(result.isError).not.toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const parsed = parsedToolPayload(result);
    expect(parsed.context.action).toBe("policy blocking vulnerabilities");
    expect(parsed.anchore).toEqual({
      reportVersion: POLICY_BLOCKING_VULNS_REPORT_VERSION,
      policyRemediationStatus: "already_green",
      selectedImage: { digest: "sha256:green" },
      blockingVulnerabilities: [],
    });
  });

  it("returns a compact exact CVE blocker with fixed version and vulnerability locations", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            status: "fail",
            gates: [
              {
                gate: "vulnerability",
                action: "stop",
                vulnerability_id: "CVE-2026-0001",
                trigger: "package",
                reason: "Critical vulnerable package",
              },
            ],
          }),
          { status: 200 },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            vulnerabilities: [
              {
                vulnerability_id: "CVE-2026-0001",
                severity: "Critical",
                package_name: "openssl",
                package_version: "3.0.0",
                package_type: "deb",
                fixed_version: "3.0.1",
                locations: [{ path: "/usr/lib/libssl.so", kind: "file" }],
              },
            ],
          }),
          { status: 200 },
        ),
      );

    const result = await runPolicyBlockingVulnerabilities(
      { image_digest: "sha256:red" },
      { connection: testConnection(), fetch: fetchMock },
    );

    expect(result.isError).not.toBe(true);
    const parsed = parsedToolPayload(result);
    expect(parsed.anchore.policyRemediationStatus).toBe("blocking_vulnerabilities_found");
    expect(parsed.anchore.blockingVulnerabilities).toEqual([
      {
        id: "CVE-2026-0001",
        severity: "Critical",
        packageName: "openssl",
        packageVersion: "3.0.0",
        packageType: "deb",
        fixedVersion: "3.0.1",
        imageLocations: [
          {
            path: "/usr/lib/libssl.so",
            kind: "file",
            source: "vulnerability",
          },
        ],
        policy: {
          gate: "vulnerability",
          trigger: "package",
          reason: "Critical vulnerable package",
        },
        evidence: {
          matchedBy: ["vulnerabilityId"],
          policyFindingRef: "gates[0]",
        },
      },
    ]);
  });

  it("returns an MCP error when a red policy has no proven vulnerability fix", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            status: "fail",
            gates: [{ gate: "dockerfile", action: "stop", reason: "not a vuln gate" }],
          }),
          { status: 200 },
        ),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ vulnerabilities: [] }), { status: 200 }),
      );

    const result = await runPolicyBlockingVulnerabilities(
      { image_digest: "sha256:no-proof" },
      { connection: testConnection(), fetch: fetchMock },
    );

    expect(result.isError).toBe(true);
    const parsed = JSON.parse(textPayload(result)) as {
      error: true;
      policyRemediationStatus: string;
    };
    expect(parsed.error).toBe(true);
    expect(parsed.policyRemediationStatus).toBe(
      "red_policy_without_proven_vulnerability_fix",
    );
  });

  it("returns image selection error without fetching policy or vulnerabilities after selection fails", async () => {
    const fetchMock = vi.fn();

    const result = await runPolicyBlockingVulnerabilities(
      { image_digest: "sha256:a", image_reference: "docker.io/library/nginx:latest" },
      { connection: testConnection(), fetch: fetchMock },
    );

    expect(result.isError).toBe(true);
    expect(fetchMock).not.toHaveBeenCalled();
    const parsed = JSON.parse(textPayload(result)) as {
      error: true;
      policyRemediationStatus: string;
      message: string;
    };
    expect(parsed.error).toBe(true);
    expect(parsed.policyRemediationStatus).toBe("image_selection_error");
    expect(parsed.message).toMatch(/exactly one/);
  });

  it("puts optional tag and base_digest only in the policy check query", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ status: "pass" }), { status: 200 }),
    );

    await runPolicyBlockingVulnerabilities(
      {
        image_digest: "sha256:query",
        tag: "docker.io/library/nginx:latest",
        base_digest: "sha256:base",
      },
      { connection: testConnection(), fetch: fetchMock },
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const policyUrl = String(fetchMock.mock.calls[0]?.[0]);
    expect(policyUrl).toContain("/v2/images/sha256%3Aquery/check?");
    expect(policyUrl).toContain(`tag=${encodeURIComponent("docker.io/library/nginx:latest")}`);
    expect(policyUrl).toContain(`base_digest=${encodeURIComponent("sha256:base")}`);
  });

  it("does not include raw policy or vulnerability payload fields in the success payload", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            status: "fail",
            gates: [{ gate: "vulnerability", action: "stop", vulnerability_id: "CVE-1" }],
          }),
          { status: 200 },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            vulnerabilities: [
              {
                vulnerability_id: "CVE-1",
                package_name: "pkg",
                package_version: "1",
                fixed_version: "2",
              },
            ],
          }),
          { status: 200 },
        ),
      );

    const result = await runPolicyBlockingVulnerabilities(
      { image_digest: "sha256:compact" },
      { connection: testConnection(), fetch: fetchMock },
    );

    expect(result.isError).not.toBe(true);
    const { anchore } = parsedToolPayload(result);
    expect(anchore.policyCheck).toBeUndefined();
    expect(anchore.policyData).toBeUndefined();
    expect(anchore.vulnerabilities).toBeUndefined();
    expect(anchore.vulnerabilityData).toBeUndefined();
  });
});
