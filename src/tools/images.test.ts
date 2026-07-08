import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clearOpenApiCacheForTests } from "../anchore/openapi-fetch.js";
import type { ResolvedAnchoreConnection } from "../config/connection.js";
import { formatAnchoreToolJson } from "./format.js";
import { runListImages } from "./images.js";

function testConnection(apiVersion: "v1" | "v2" = "v2"): ResolvedAnchoreConnection {
  return {
    baseUrl: "https://anchore.example.com",
    username: "_api_key",
    password: "test-token-value",
    account: "acct1",
    apiVersion,
  };
}

beforeEach(() => {
  process.env.ANCHORE_HTTP_MAX_RETRIES = "0";
});

afterEach(() => {
  clearOpenApiCacheForTests();
  delete process.env.ANCHORE_HTTP_MAX_RETRIES;
  vi.restoreAllMocks();
});

describe("runListImages", () => {
  it("returns context, summary, and anchore payload on success", async () => {
    const connection = testConnection();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ images: [{ imageDigest: "sha256:abc" }] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const result = await runListImages({}, { connection, fetch: fetchMock });
    expect(result.isError).not.toBe(true);
    const text = result.content?.[0]?.type === "text" ? result.content[0].text : "";
    const parsed = JSON.parse(text) as {
      context: { baseUrl: string; account?: string; apiVersion: string };
      summary: string;
      anchore: { images: unknown[] };
    };
    expect(parsed.context.baseUrl).toBe("https://anchore.example.com");
    expect(parsed.context.account).toBe("acct1");
    expect(parsed.context.apiVersion).toBe("v2");
    expect(parsed.summary).toMatch(/1 image/);
    expect(parsed.anchore.images).toHaveLength(1);
    expect(fetchMock).toHaveBeenCalledWith(
      "https://anchore.example.com/v2/images",
      expect.anything(),
    );
  });

  it("uses /v1/images when ANCHORE_API_VERSION is v1", async () => {
    const connection = testConnection("v1");
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ images: [] }), { status: 200 }),
    );
    await runListImages({}, { connection, fetch: fetchMock });
    expect(fetchMock.mock.calls[0][0]).toBe("https://anchore.example.com/v1/images");
  });

  it("maps the public fulltag input to v1 fulltag", async () => {
    const connection = testConnection("v1");
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ images: [] }), { status: 200 }),
    );

    await runListImages(
      { fulltag: "registry.example.com/team/app:1" },
      { connection, fetch: fetchMock },
    );

    const url = String(fetchMock.mock.calls[0][0]);
    expect(url).toContain("/v1/images?fulltag=");
    expect(url).not.toContain("full_tag=");
  });

  it("uses the v1 fulltag fallback when OpenAPI discovery fails", async () => {
    const connection = testConnection("v1");
    const fetchMock = vi.fn().mockImplementation((url: string) => {
      if (url.includes("/openapi.json")) {
        return new Response("unavailable", { status: 503 });
      }
      return new Response(JSON.stringify({ images: [] }), { status: 200 });
    });

    await runListImages(
      { list_query: { fulltag: "registry.example.com/team/app:1" } },
      { connection, fetch: fetchMock },
    );

    const imagesCall = fetchMock.mock.calls.find((call) =>
      String(call[0]).includes("/v1/images"),
    );
    expect(imagesCall).toBeDefined();
    expect(String(imagesCall![0])).toContain("fulltag=");
    expect(String(imagesCall![0])).not.toContain("full_tag=");
  });

  it("summarizes v2 items-shaped list responses", async () => {
    const connection = testConnection();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ items: [{ image_digest: "sha256:x" }] }), {
        status: 200,
      }),
    );
    const result = await runListImages({}, { connection, fetch: fetchMock });
    const text = result.content?.[0]?.type === "text" ? result.content[0].text : "";
    const parsed = JSON.parse(text) as { summary: string };
    expect(parsed.summary).toMatch(/Found 1 image/);
  });

  it("uses empty-result messaging", async () => {
    const connection = testConnection();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ images: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const result = await runListImages({}, { connection, fetch: fetchMock });
    const text = result.content?.[0]?.type === "text" ? result.content[0].text : "";
    const parsed = JSON.parse(text) as { summary: string };
    expect(parsed.summary).toMatch(/No images matched/i);
  });

  it("merges multiple pages when Link rel=next is present", async () => {
    const connection = testConnection();
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ images: [{ imageDigest: "sha256:aa" }] }), {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            Link: '</v2/images?p=2>; rel="next"',
          },
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ images: [{ imageDigest: "sha256:bb" }] }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    const result = await runListImages({}, { connection, fetch: fetchMock });
    expect(result.isError).not.toBe(true);
    const text = result.content?.[0]?.type === "text" ? result.content[0].text : "";
    const parsed = JSON.parse(text) as { anchore: { images: unknown[] } };
    expect(parsed.anchore.images).toHaveLength(2);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("merges allowlisted list_query into the images request URL", async () => {
    const connection = testConnection();
    const fetchMock = vi.fn().mockImplementation((url: string) => {
      if (url.includes("/openapi.json")) {
        return new Response(
          JSON.stringify({
            paths: {
              "/v2/images": {
                get: {
                  parameters: [{ name: "name", in: "query" }],
                },
              },
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      return new Response(JSON.stringify({ images: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    await runListImages(
      { list_query: { name: "my-filter" } },
      { connection, fetch: fetchMock },
    );
    const imagesCall = fetchMock.mock.calls.find((c) =>
      String(c[0]).includes("/v2/images"),
    );
    expect(imagesCall).toBeDefined();
    expect(String(imagesCall![0])).toContain("name=my-filter");
  });

  it("notes rejected list_query keys in the summary", async () => {
    const connection = testConnection();
    const fetchMock = vi.fn().mockImplementation(
      () =>
        new Response(JSON.stringify({ images: [] }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    );
    const result = await runListImages(
      { list_query: { __not_in_allowlist__: "x" } },
      { connection, fetch: fetchMock },
    );
    const text = result.content?.[0]?.type === "text" ? result.content[0].text : "";
    const parsed = JSON.parse(text) as { summary: string };
    expect(parsed.summary).toMatch(/dropped/i);
    expect(parsed.summary).toMatch(/__not_in_allowlist__/);
  });

  it("appends query parameters when provided", async () => {
    const connection = testConnection();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ images: [] }), { status: 200 }),
    );
    await runListImages(
      { fulltag: "docker.io/library/nginx:latest", vulnerability_id: "CVE-2024-1" },
      { connection, fetch: fetchMock },
    );
    const url = fetchMock.mock.calls[0][0] as string;
    expect(url).toContain("full_tag=");
    expect(url).not.toContain("fulltag=");
    expect(url).toContain("vulnerability_id=");
  });

  it("R14: formatAnchoreToolJson masks email in summary line", () => {
    const json = formatAnchoreToolJson(
      {
        baseUrl: "https://anchore.enterprise.local",
        apiVersion: "v2",
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

  it("fails gracefully when env is missing and no connection is injected", async () => {
    const origUrl = process.env.ANCHORE_URL;
    const origTok = process.env.ANCHORE_TOKEN;
    delete process.env.ANCHORE_URL;
    delete process.env.ANCHORE_TOKEN;
    try {
      const result = await runListImages({});
      expect(result.isError).toBe(true);
    } finally {
      if (origUrl !== undefined) {
        process.env.ANCHORE_URL = origUrl;
      }
      if (origTok !== undefined) {
        process.env.ANCHORE_TOKEN = origTok;
      }
    }
  });

  it("does not write large JSON to stderr on success", async () => {
    const connection = testConnection();
    const spy = vi.spyOn(process.stderr, "write");
    const huge = { images: [{ detail: "x".repeat(30_000) }] };
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(huge), { status: 200 }),
    );
    await runListImages({}, { connection, fetch: fetchMock });
    const written = spy.mock.calls.map((c) => String(c[0])).join("");
    expect(written).toBe("");
    spy.mockRestore();
  });
});
