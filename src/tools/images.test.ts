import { afterEach, describe, expect, it, vi } from "vitest";
import { ProfileRegistry } from "../config/profiles.js";
import { formatAnchoreToolJson } from "./format.js";
import { runListImages } from "./images.js";

const ENV_KEY = "ANCHORE_MCP_UNIT_TOKEN";

function testRegistry(): ProfileRegistry {
  process.env[ENV_KEY] = "test-token-value";
  return new ProfileRegistry(
    {
      defaultProfile: "prod",
      profiles: {
        prod: {
          baseUrl: "https://anchore.example.com",
          username: "_api_key",
          passwordEnv: ENV_KEY,
          account: "acct1",
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

describe("runListImages", () => {
  it("returns context, summary, and anchore payload on success", async () => {
    const registry = testRegistry();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ images: [{ imageDigest: "sha256:abc" }] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const result = await runListImages(registry, {}, { fetch: fetchMock });
    expect(result.isError).not.toBe(true);
    const text = result.content?.[0]?.type === "text" ? result.content[0].text : "";
    const parsed = JSON.parse(text) as {
      context: { profileName: string; baseUrl: string; account?: string };
      summary: string;
      anchore: { images: unknown[] };
    };
    expect(parsed.context.profileName).toBe("prod");
    expect(parsed.context.baseUrl).toBe("https://anchore.example.com");
    expect(parsed.context.account).toBe("acct1");
    expect(parsed.summary).toMatch(/1 image/);
    expect(parsed.anchore.images).toHaveLength(1);
    expect(fetchMock).toHaveBeenCalledWith(
      "https://anchore.example.com/v1/images",
      expect.anything(),
    );
  });

  it("uses empty-result messaging", async () => {
    const registry = testRegistry();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ images: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const result = await runListImages(registry, {}, { fetch: fetchMock });
    const text = result.content?.[0]?.type === "text" ? result.content[0].text : "";
    const parsed = JSON.parse(text) as { summary: string };
    expect(parsed.summary).toMatch(/No images matched/i);
  });

  it("appends query parameters when provided", async () => {
    const registry = testRegistry();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ images: [] }), { status: 200 }),
    );
    await runListImages(
      registry,
      { fulltag: "docker.io/library/nginx:latest", vulnerability_id: "CVE-2024-1" },
      { fetch: fetchMock },
    );
    const url = fetchMock.mock.calls[0][0] as string;
    expect(url).toContain("fulltag=");
    expect(url).toContain("vulnerability_id=");
  });

  it("R14: formatAnchoreToolJson masks email in summary line", () => {
    const json = formatAnchoreToolJson(
      {
        profileName: "prod",
        baseUrl: "https://anchore.enterprise.local",
        action: "list images",
      },
      "Contact leaks@example.com for access.",
      { images: [] },
    );
    const o = JSON.parse(json) as { summary: string; warnings: string[] };
    expect(o.summary).toContain("[email redacted]");
    expect(o.summary).not.toContain("leaks@");
    expect(o.warnings.length).toBeGreaterThan(0);
  });

  it("does not write large JSON to stderr on success", async () => {
    const registry = testRegistry();
    const spy = vi.spyOn(process.stderr, "write");
    const huge = { images: [{ detail: "x".repeat(30_000) }] };
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(huge), { status: 200 }),
    );
    await runListImages(registry, {}, { fetch: fetchMock });
    const written = spy.mock.calls.map((c) => String(c[0])).join("");
    expect(written).toBe("");
    spy.mockRestore();
  });
});
