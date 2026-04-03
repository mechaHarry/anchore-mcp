import { afterEach, describe, expect, it, vi } from "vitest";
import type { ResolvedAnchoreConnection } from "../config/connection.js";
import {
  REMEDIATION_HANDOFF_VERSION,
  runRemediationHandoff,
} from "./remediation-handoff.js";

function testConnection(apiVersion: "v1" | "v2" = "v2"): ResolvedAnchoreConnection {
  return {
    baseUrl: "https://anchore.example.com",
    username: "_api_key",
    password: "test-token",
    apiVersion,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("runRemediationHandoff", () => {
  it("builds a versioned bundle with image detail, vulnerabilities, and policy (v2)", async () => {
    const connection = testConnection();
    const digest = "sha256:abc123";
    const fetchMock = vi.fn().mockImplementation((url: string) => {
      if (url.includes("/vuln/all")) {
        return Promise.resolve(
          new Response(
            JSON.stringify({ vulnerabilities: [{ id: "CVE-2024-1" }] }),
            { status: 200 },
          ),
        );
      }
      if (url.includes("/check")) {
        return Promise.resolve(
          new Response(JSON.stringify({ status: "pass" }), { status: 200 }),
        );
      }
      if (url.includes(`/v2/images/${encodeURIComponent(digest)}`)) {
        return Promise.resolve(
          new Response(
            JSON.stringify({ image_digest: digest, distro: "debian" }),
            { status: 200 },
          ),
        );
      }
      return Promise.resolve(new Response("not found", { status: 404 }));
    });

    const result = await runRemediationHandoff(
      { image_digest: digest },
      { connection, fetch: fetchMock },
    );

    expect(result.isError).not.toBe(true);
    const text = result.content?.[0]?.type === "text" ? result.content[0].text : "";
    const parsed = JSON.parse(text) as {
      context: { action: string };
      summary: string;
      sizeBytes: number;
      anchore: {
        handoffVersion: string;
        deployment: { baseUrl: string; apiVersion: string };
        imageDigest: string;
        evidence: {
          imageDetail: { image_digest: string };
          vulnerabilities: { vulnerabilities: unknown[] };
          policyCheck: { status: string };
        };
      };
    };

    expect(parsed.context.action).toBe("remediation handoff");
    expect(parsed.summary).toMatch(/Remediation handoff/);
    expect(parsed.sizeBytes).toBeGreaterThan(0);
    expect(parsed.anchore.handoffVersion).toBe(REMEDIATION_HANDOFF_VERSION);
    expect(parsed.anchore.deployment.baseUrl).toBe("https://anchore.example.com");
    expect(parsed.anchore.imageDigest).toBe(digest);
    expect(parsed.anchore.evidence.imageDetail.image_digest).toBe(digest);
    expect(parsed.anchore.evidence.vulnerabilities.vulnerabilities).toHaveLength(1);
    expect(parsed.anchore.evidence.policyCheck?.status).toBe("pass");

    expect(fetchMock.mock.calls.length).toBe(3);
  });

  it("omits policy when include_policy_check is false", async () => {
    const connection = testConnection();
    const digest = "sha256:x";
    const fetchMock = vi.fn().mockImplementation((url: string) => {
      if (url.includes("/vuln/all")) {
        return Promise.resolve(
          new Response(JSON.stringify({ vulnerabilities: [] }), { status: 200 }),
        );
      }
      if (url.includes(`/v2/images/${encodeURIComponent(digest)}`)) {
        return Promise.resolve(
          new Response(JSON.stringify({ image_digest: digest }), { status: 200 }),
        );
      }
      return Promise.resolve(new Response("not found", { status: 404 }));
    });

    const result = await runRemediationHandoff(
      { image_digest: digest, include_policy_check: false },
      { connection, fetch: fetchMock },
    );

    expect(result.isError).not.toBe(true);
    const text = result.content?.[0]?.type === "text" ? result.content[0].text : "";
    const parsed = JSON.parse(text) as {
      anchore: { evidence: Record<string, unknown> };
    };
    expect(parsed.anchore.evidence.policyCheck).toBeUndefined();
    expect(fetchMock.mock.calls.length).toBe(2);
  });

  it("rejects empty digest", async () => {
    const result = await runRemediationHandoff({ image_digest: "   " });
    expect(result.isError).toBe(true);
  });

  it("passes tag and base_digest to policy path when included", async () => {
    const connection = testConnection();
    const digest = "sha256:p";
    const fetchMock = vi.fn().mockImplementation((url: string) => {
      if (url.includes("/vuln/all") || url.includes(`/v2/images/${encodeURIComponent(digest)}`)) {
        return Promise.resolve(new Response("{}", { status: 200 }));
      }
      if (url.includes("/check")) {
        return Promise.resolve(new Response("{}", { status: 200 }));
      }
      return Promise.resolve(new Response("not found", { status: 404 }));
    });

    await runRemediationHandoff(
      {
        image_digest: digest,
        tag: "docker.io/nginx:latest",
        base_digest: "sha256:base",
      },
      { connection, fetch: fetchMock },
    );

    const policyCall = fetchMock.mock.calls.find((c) =>
      String(c[0]).includes("/check"),
    );
    expect(policyCall).toBeDefined();
    const policyUrl = String(policyCall![0]);
    expect(policyUrl).toContain("tag=");
    expect(policyUrl).toContain("base_digest=");
  });
});
