import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ResolvedAnchoreConnection } from "../config/connection.js";
import * as safeLog from "../logging/safe-log.js";
import {
  POLICY_BLOCKING_VULN_EVIDENCE_MAX_RESPONSE_BYTES,
  POLICY_BLOCKING_VULNS_REPORT_VERSION,
  runPolicyBlockingVulnerabilities,
  type PolicyBlockingVulnerabilitiesErrorPayload,
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

function okList(items: unknown[]): Response {
  return new Response(JSON.stringify({ items }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
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

  it("treats action-only policies with no blocking actions as already green", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          findings: [
            { gate: "vulnerabilities", trigger: "package", action: "WARN" },
            { gate: "vulnerabilities", trigger: "package", action: "GO" },
          ],
        }),
        { status: 200 },
      ),
    );

    const result = await runPolicyBlockingVulnerabilities(
      { image_digest: "sha256:warn-only" },
      { connection: testConnection(), fetch: fetchMock },
    );

    expect(result.isError).not.toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const parsed = parsedToolPayload(result);
    expect(parsed.anchore.policyRemediationStatus).toBe("already_green");
    expect(parsed.anchore.blockingVulnerabilities).toEqual([]);
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

  it("returns a compact blocker for Anchore trigger_id CVE findings", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            findings: [
              {
                gate: "vulnerabilities",
                trigger: "package",
                action: "STOP",
                trigger_id: "CVE-2019-5435+curl",
                message: "package curl has CVE-2019-5435",
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
                vulnerability_id: "CVE-2019-5435",
                package_name: "curl",
                package_version: "7.64.0",
                fixed_version: "7.64.1",
              },
            ],
          }),
          { status: 200 },
        ),
      );

    const result = await runPolicyBlockingVulnerabilities(
      { image_digest: "sha256:trigger-id" },
      { connection: testConnection(), fetch: fetchMock },
    );

    expect(result.isError).not.toBe(true);
    const parsed = parsedToolPayload(result);
    expect(parsed.anchore.blockingVulnerabilities).toEqual([
      expect.objectContaining({
        id: "CVE-2019-5435",
        packageName: "curl",
        fixedVersion: "7.64.1",
        evidence: {
          matchedBy: ["vulnerabilityId"],
          policyFindingRef: "findings[0]",
        },
      }),
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
    expect(parsed).toMatchObject({
      reportVersion: POLICY_BLOCKING_VULNS_REPORT_VERSION,
      selectedImage: { digest: "sha256:no-proof" },
    });
  });

  it("returns a clean MCP error when vulnerability evidence exceeds the response cap", async () => {
    const rawBodyMarker = "RAW_BODY_MARKER_SHOULD_NOT_LEAK";
    const oversizedVulnerabilityBody =
      JSON.stringify({ vulnerabilities: [{ note: rawBodyMarker }] }) +
      " ".repeat(POLICY_BLOCKING_VULN_EVIDENCE_MAX_RESPONSE_BYTES + 1);
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
                vulnerability_id: "CVE-2026-0002",
              },
            ],
          }),
          { status: 200 },
        ),
      )
      .mockResolvedValueOnce(
        new Response(oversizedVulnerabilityBody, { status: 200 }),
      );

    const result = await runPolicyBlockingVulnerabilities(
      { image_digest: "sha256:oversized" },
      { connection: testConnection(), fetch: fetchMock },
    );

    expect(result.isError).toBe(true);
    const parsed = JSON.parse(textPayload(result)) as PolicyBlockingVulnerabilitiesErrorPayload;
    expect(parsed.error).toBe(true);
    expect(parsed.message).toMatch(/exceeding/i);
    expect(parsed.message).not.toContain(rawBodyMarker);
    expect(safeLog.logStderrLine).toHaveBeenCalledTimes(1);
    expect(vi.mocked(safeLog.logStderrLine).mock.calls[0]?.[0]).toMatch(/exceeding/i);
    expect(vi.mocked(safeLog.logStderrLine).mock.calls[0]?.[0]).not.toContain(
      rawBodyMarker,
    );
  });

  it("sanitizes generic unexpected errors before returning or logging them", async () => {
    const rawBodyMarker = "RAW_BODY_MARKER secret-ish response body";
    const fetchMock = vi.fn().mockRejectedValue(new Error(rawBodyMarker));

    const result = await runPolicyBlockingVulnerabilities(
      { image_digest: "sha256:policy-error" },
      { connection: testConnection(), fetch: fetchMock },
    );

    expect(result.isError).toBe(true);
    expect(textPayload(result)).not.toContain("RAW_BODY_MARKER");
    expect(safeLog.logStderrLine).toHaveBeenCalledTimes(1);
    expect(vi.mocked(safeLog.logStderrLine).mock.calls[0]?.[0]).not.toContain(
      "RAW_BODY_MARKER",
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
    expect(parsed.message).toBe(
      "Supply exactly one of image_digest, image_reference, or the image_registry and image_repository pair.",
    );
  });

  it.each([
    { image_registry: "registry.example.com" },
    { image_repository: "team/app" },
  ])("rejects an incomplete component pair without fetching: %o", async (args) => {
    const fetchMock = vi.fn();

    const result = await runPolicyBlockingVulnerabilities(args, {
      connection: testConnection(),
      fetch: fetchMock,
    });

    expect(fetchMock).not.toHaveBeenCalled();
    expect(JSON.parse(textPayload(result))).toMatchObject({
      error: true,
      policyRemediationStatus: "image_selection_error",
      message: "Supply image_registry and image_repository together.",
    });
  });

  it.each([
    {
      image_digest: "sha256:a",
      image_registry: "registry.example.com",
      image_repository: "team/app",
    },
    {
      image_reference: "registry.example.com/team/app:latest",
      image_registry: "registry.example.com",
      image_repository: "team/app",
    },
  ])("rejects a mixed component-pair locator without fetching: %o", async (args) => {
    const fetchMock = vi.fn();

    const result = await runPolicyBlockingVulnerabilities(args, {
      connection: testConnection(),
      fetch: fetchMock,
    });

    expect(fetchMock).not.toHaveBeenCalled();
    expect(JSON.parse(textPayload(result))).toMatchObject({
      error: true,
      policyRemediationStatus: "image_selection_error",
      message:
        "Supply exactly one of image_digest, image_reference, or the image_registry and image_repository pair.",
    });
  });

  it.each([
    {
      args: { image_registry: "", image_repository: "team/app" },
      message: "image_registry is empty.",
    },
    {
      args: { image_registry: "r".repeat(1025), image_repository: "team/app" },
      message: "image_registry is too long.",
    },
    {
      args: { image_registry: "registry.example.com\n", image_repository: "team/app" },
      message: "image_registry contains invalid control characters.",
    },
    {
      args: { image_registry: "registry.example.com/path", image_repository: "team/app" },
      message: "image_registry must not contain '/'.",
    },
    {
      args: { image_registry: "registry.example.com", image_repository: "" },
      message: "image_repository is empty.",
    },
    {
      args: { image_registry: "registry.example.com", image_repository: "r".repeat(1025) },
      message: "image_repository is too long.",
    },
    {
      args: { image_registry: "registry.example.com", image_repository: "team\u0000/app" },
      message: "image_repository contains invalid control characters.",
    },
    {
      args: { image_registry: "registry.example.com", image_repository: "/team/app" },
      message: "image_repository must not begin or end with '/'.",
    },
    {
      args: { image_registry: "registry.example.com", image_repository: "team/app:latest" },
      message: "image_repository must not include an image tag.",
    },
  ])("returns the stable component validation message: $message", async ({ args, message }) => {
    const fetchMock = vi.fn();

    const result = await runPolicyBlockingVulnerabilities(args, {
      connection: testConnection(),
      fetch: fetchMock,
    });

    expect(fetchMock).not.toHaveBeenCalled();
    expect(JSON.parse(textPayload(result))).toMatchObject({
      error: true,
      policyRemediationStatus: "image_selection_error",
      message,
    });
  });

  it("sanitizes generic image selection errors before returning them", async () => {
    const rawBodyMarker = "RAW_BODY_MARKER secret-ish selection body";
    const fetchMock = vi.fn().mockRejectedValue(new Error(rawBodyMarker));

    const result = await runPolicyBlockingVulnerabilities(
      { image_reference: "docker.io/library/nginx:latest" },
      { connection: testConnection(), fetch: fetchMock },
    );

    expect(result.isError).toBe(true);
    expect(textPayload(result)).not.toContain("RAW_BODY_MARKER");
    const parsed = JSON.parse(textPayload(result)) as {
      policyRemediationStatus: string;
    };
    expect(parsed.policyRemediationStatus).toBe("image_selection_error");
    for (const call of vi.mocked(safeLog.logStderrLine).mock.calls) {
      expect(call[0]).not.toContain("RAW_BODY_MARKER");
    }
  });

  it("does not trust an ambiguity-shaped backend error", async () => {
    const token = "AKIAEXAMPLESECRET1234";
    const fetchMock = vi.fn().mockRejectedValue(
      new Error(
        `Newest analyzed image is ambiguous: 2 digests share timestamp ${token}.`,
      ),
    );

    const result = await runPolicyBlockingVulnerabilities(
      { image_reference: "docker.io/library/nginx:latest" },
      { connection: testConnection(), fetch: fetchMock },
    );

    expect(result.isError).toBe(true);
    expect(JSON.parse(textPayload(result))).toMatchObject({
      error: true,
      message: "Image selection failed before policy evaluation.",
      policyRemediationStatus: "image_selection_error",
    });
    expect(textPayload(result)).not.toContain(token);
    for (const call of vi.mocked(safeLog.logStderrLine).mock.calls) {
      expect(call[0]).not.toContain(token);
    }
  });

  it.each([
    {
      args: { image_reference: "docker.io/library/nginx:latest" },
      message: "image_reference RAW_BODY_MARKER secret-ish selection body",
    },
    {
      args: {
        image_registry: "docker.io",
        image_repository: "library/nginx",
      },
      message: "image_repository RAW_BODY_MARKER secret-ish selection body",
    },
    {
      args: {
        image_registry: "docker.io",
        image_repository: "library/nginx",
      },
      message: "image_registry RAW_BODY_MARKER secret-ish selection body",
    },
    {
      args: { image_reference: "docker.io/library/nginx:latest" },
      message: "Image list enumeration incomplete RAW_BODY_MARKER secret-ish selection body",
    },
  ])("sanitizes selection messages with unsafe allowed prefixes: $message", async ({ args, message }) => {
    const fetchMock = vi.fn().mockRejectedValue(new Error(message));

    const result = await runPolicyBlockingVulnerabilities(
      args,
      { connection: testConnection(), fetch: fetchMock },
    );

    expect(result.isError).toBe(true);
    expect(textPayload(result)).not.toContain("RAW_BODY_MARKER");
    const parsed = JSON.parse(textPayload(result)) as {
      policyRemediationStatus: string;
    };
    expect(parsed.policyRemediationStatus).toBe("image_selection_error");
    for (const call of vi.mocked(safeLog.logStderrLine).mock.calls) {
      expect(call[0]).not.toContain("RAW_BODY_MARKER");
    }
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

  it("uses the selected image reference as the policy tag when none is supplied", async () => {
    const reference = "containers.example.com/psf/help-site:4";
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        okList([
          {
            image_digest: "sha256:selected",
            analyzed_at: "2026-04-24T00:00:00Z",
            image_detail: [
              {
                registry: "containers.example.com",
                repo: "psf/help-site",
                tag: "4",
                full_tag: reference,
              },
            ],
          },
        ]),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ status: "pass" }), { status: 200 }),
      );

    const result = await runPolicyBlockingVulnerabilities(
      {
        image_registry: "containers.example.com",
        image_repository: "psf/help-site",
      },
      { connection: testConnection(), fetch: fetchMock },
    );

    expect(result.isError).not.toBe(true);
    const policyUrl = String(fetchMock.mock.calls[1]?.[0]);
    expect(policyUrl).toContain("/v2/images/sha256%3Aselected/check?");
    expect(policyUrl).toContain(`tag=${encodeURIComponent(reference)}`);
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
