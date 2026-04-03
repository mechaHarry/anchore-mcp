import { afterEach, describe, expect, it, vi } from "vitest";
import type { ResolvedAnchoreConnection } from "../config/connection.js";
import { runImageVulnerabilities } from "./vulnerabilities.js";

function testConnection(): ResolvedAnchoreConnection {
  return {
    baseUrl: "https://anchore.example.com",
    username: "_api_key",
    password: "test-token",
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("runImageVulnerabilities", () => {
  it("fetches vulnerabilities by encoded digest", async () => {
    const connection = testConnection();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          vulnerabilities: [{ vuln: "CVE-2024-1" }],
        }),
        { status: 200 },
      ),
    );
    const digest = "sha256:abcdef0123456789";
    const result = await runImageVulnerabilities(
      connection,
      { image_digest: digest },
      { fetch: fetchMock },
    );
    expect(result.isError).not.toBe(true);
    const url = fetchMock.mock.calls[0][0] as string;
    expect(url).toContain(encodeURIComponent(digest));
    expect(url).toContain("/vulnerabilities");
    const text = result.content?.[0]?.type === "text" ? result.content[0].text : "";
    const parsed = JSON.parse(text) as {
      context: { baseUrl: string };
      summary: string;
      anchore: { vulnerabilities: unknown[] };
    };
    expect(parsed.context.baseUrl).toBe("https://anchore.example.com");
    expect(parsed.summary).toMatch(/vulnerability record/);
    expect(parsed.anchore.vulnerabilities).toHaveLength(1);
  });

  it("returns explicit empty summary when no CVEs", async () => {
    const connection = testConnection();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ vulnerabilities: [] }), { status: 200 }),
    );
    const result = await runImageVulnerabilities(
      connection,
      { image_digest: "sha256:x" },
      { fetch: fetchMock },
    );
    const text = result.content?.[0]?.type === "text" ? result.content[0].text : "";
    const parsed = JSON.parse(text) as { summary: string };
    expect(parsed.summary).toMatch(/No vulnerabilities reported/i);
  });

  it("rejects empty digest", async () => {
    const connection = testConnection();
    const result = await runImageVulnerabilities(connection, { image_digest: "   " });
    expect(result.isError).toBe(true);
  });
});
