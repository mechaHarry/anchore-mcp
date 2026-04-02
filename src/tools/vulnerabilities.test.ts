import { afterEach, describe, expect, it, vi } from "vitest";
import { ProfileRegistry } from "../config/profiles.js";
import { runImageVulnerabilities } from "./vulnerabilities.js";

const ENV_KEY = "ANCHORE_MCP_UNIT_TOKEN_V";

function testRegistry(): ProfileRegistry {
  process.env[ENV_KEY] = "test-token";
  return new ProfileRegistry(
    {
      defaultProfile: "prod",
      profiles: {
        prod: {
          baseUrl: "https://anchore.example.com",
          username: "_api_key",
          passwordEnv: ENV_KEY,
        },
      },
    },
    "/tmp/anchore-mcp-unit.yaml",
    true,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  delete process.env[ENV_KEY];
});

describe("runImageVulnerabilities", () => {
  it("fetches vulnerabilities by encoded digest", async () => {
    const registry = testRegistry();
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
      registry,
      { image_digest: digest },
      { fetch: fetchMock },
    );
    expect(result.isError).not.toBe(true);
    const url = fetchMock.mock.calls[0][0] as string;
    expect(url).toContain(encodeURIComponent(digest));
    expect(url).toContain("/vulnerabilities");
    const text = result.content?.[0]?.type === "text" ? result.content[0].text : "";
    const parsed = JSON.parse(text) as {
      context: { profileName: string };
      summary: string;
      anchore: { vulnerabilities: unknown[] };
    };
    expect(parsed.context.profileName).toBe("prod");
    expect(parsed.summary).toMatch(/vulnerability record/);
    expect(parsed.anchore.vulnerabilities).toHaveLength(1);
  });

  it("returns explicit empty summary when no CVEs", async () => {
    const registry = testRegistry();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ vulnerabilities: [] }), { status: 200 }),
    );
    const result = await runImageVulnerabilities(
      registry,
      { image_digest: "sha256:x" },
      { fetch: fetchMock },
    );
    const text = result.content?.[0]?.type === "text" ? result.content[0].text : "";
    const parsed = JSON.parse(text) as { summary: string };
    expect(parsed.summary).toMatch(/No vulnerabilities reported/i);
  });

  it("rejects empty digest", async () => {
    const registry = testRegistry();
    const result = await runImageVulnerabilities(registry, { image_digest: "   " });
    expect(result.isError).toBe(true);
  });
});
