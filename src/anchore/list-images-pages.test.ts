import { describe, expect, it, vi } from "vitest";
import type { ResolvedAnchoreConnection } from "../config/connection.js";
import { createAnchoreClient } from "./client.js";
import { fetchAllListImagesPages } from "./list-images-pages.js";

function testConn(): ResolvedAnchoreConnection {
  return {
    baseUrl: "https://anchore.example.com",
    username: "_api_key",
    password: "t",
    apiVersion: "v2",
  };
}

describe("fetchAllListImagesPages", () => {
  it("merges a single page when no continuation is present", async () => {
    const connection = testConn();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ images: [{ imageDigest: "sha256:aa" }] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const client = createAnchoreClient(connection, { fetch: fetchMock });
    const params = new URLSearchParams();
    const out = await fetchAllListImagesPages(client, connection, params, {
      maxPages: 10,
      maxItems: 100,
    });
    expect(out.enumerationIncomplete).toBe(false);
    expect(out.pagesFetched).toBe(1);
    expect(out.mergedBody).toEqual({
      images: [{ imageDigest: "sha256:aa" }],
    });
  });

  it("follows Link rel=next until complete", async () => {
    const connection = testConn();
    const page1 = {
      images: [{ imageDigest: "sha256:a" }],
    };
    const page2 = { images: [{ imageDigest: "sha256:b" }] };
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify(page1), {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            Link: '</v2/images?page=2>; rel="next"',
          },
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify(page2), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    const client = createAnchoreClient(connection, { fetch: fetchMock });
    const out = await fetchAllListImagesPages(
      client,
      connection,
      new URLSearchParams(),
      { maxPages: 10, maxItems: 100 },
    );
    expect(out.enumerationIncomplete).toBe(false);
    expect(out.pagesFetched).toBe(2);
    expect(out.mergedBody).toEqual({
      images: [{ imageDigest: "sha256:a" }, { imageDigest: "sha256:b" }],
    });
    expect(fetchMock.mock.calls[1][0]).toContain("/v2/images");
  });

  it("sets enumerationIncomplete when maxPages stops before end", async () => {
    const connection = testConn();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ images: [] }), {
        status: 200,
        headers: {
          Link: '</v2/images?n=2>; rel="next"',
          "Content-Type": "application/json",
        },
      }),
    );
    const client = createAnchoreClient(connection, { fetch: fetchMock });
    const out = await fetchAllListImagesPages(
      client,
      connection,
      new URLSearchParams(),
      { maxPages: 1, maxItems: 100 },
    );
    expect(out.enumerationIncomplete).toBe(true);
    expect(out.incompleteReason).toMatch(/maxPages/);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("sets enumerationIncomplete when maxItems caps row collection", async () => {
    const connection = testConn();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          images: [{ imageDigest: "sha256:1" }, { imageDigest: "sha256:2" }],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    const client = createAnchoreClient(connection, { fetch: fetchMock });
    const out = await fetchAllListImagesPages(
      client,
      connection,
      new URLSearchParams(),
      { maxPages: 10, maxItems: 1 },
    );
    expect(out.enumerationIncomplete).toBe(true);
    expect(out.incompleteReason).toMatch(/maxItems/);
    expect((out.mergedBody as { images: unknown[] }).images).toHaveLength(1);
  });

  it("uses next_page_token in body when Link is absent", async () => {
    const connection = testConn();
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            items: [{ image_digest: "sha256:x" }],
            next_page_token: "tok1",
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ items: [{ image_digest: "sha256:y" }] }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    const client = createAnchoreClient(connection, { fetch: fetchMock });
    const baseParams = new URLSearchParams();
    const out = await fetchAllListImagesPages(client, connection, baseParams, {
      maxPages: 5,
      maxItems: 100,
    });
    expect(out.pagesFetched).toBe(2);
    expect(out.enumerationIncomplete).toBe(false);
    const secondUrl = fetchMock.mock.calls[1][0] as string;
    expect(secondUrl).toContain("page_token=tok1");
  });
});
