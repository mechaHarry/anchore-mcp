import { describe, expect, it, vi } from "vitest";
import type { ResolvedAnchoreConnection } from "../config/connection.js";
import { createAnchoreClient } from "./client.js";
import { fetchAllImageTagSummaryPages } from "./image-tag-summary-pages.js";

const connection: ResolvedAnchoreConnection = {
  baseUrl: "https://anchore.example.com",
  username: "_api_key",
  password: "t",
  apiVersion: "v2",
};

function response(items: unknown[], totalRows?: number): Response {
  return new Response(
    JSON.stringify({ items, ...(totalRows === undefined ? {} : { total_rows: totalRows }) }),
    { status: 200, headers: { "Content-Type": "application/json" } },
  );
}

describe("fetchAllImageTagSummaryPages", () => {
  it("uses total_rows to continue with bounded page and limit queries", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(response([{ image_digest: "sha256:a" }], 2))
      .mockResolvedValueOnce(response([{ image_digest: "sha256:b" }], 2));
    const client = createAnchoreClient(connection, { fetch: fetchMock });

    const out = await fetchAllImageTagSummaryPages(
      client,
      connection,
      new URLSearchParams({ registry: "registry.example.com", repository: "team/app" }),
      { maxPages: 3, maxItems: 2 },
    );

    expect(out).toMatchObject({
      rows: [{ image_digest: "sha256:a" }, { image_digest: "sha256:b" }],
      pagesFetched: 2,
      enumerationIncomplete: false,
    });
    expect(fetchMock.mock.calls.map((call) => new URL(call[0] as string).searchParams.get("page"))).toEqual(["1", "2"]);
    expect(fetchMock.mock.calls[0][0]).toContain("limit=2");
  });

  it("terminates conservatively on an empty page when total_rows is missing", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(response([{ image_digest: "sha256:a" }]))
      .mockResolvedValueOnce(response([]));
    const client = createAnchoreClient(connection, { fetch: fetchMock });

    const out = await fetchAllImageTagSummaryPages(
      client,
      connection,
      new URLSearchParams({ limit: "1" }),
      { maxPages: 3, maxItems: 2 },
    );

    expect(out.enumerationIncomplete).toBe(false);
    expect(out.pagesFetched).toBe(2);
  });

  it("marks enumeration incomplete when total_rows exceeds maxItems", async () => {
    const fetchMock = vi.fn().mockResolvedValue(response([{ image_digest: "sha256:a" }], 2));
    const client = createAnchoreClient(connection, { fetch: fetchMock });

    const out = await fetchAllImageTagSummaryPages(
      client,
      connection,
      new URLSearchParams(),
      { maxPages: 3, maxItems: 1 },
    );

    expect(out.enumerationIncomplete).toBe(true);
    expect(out.incompleteReason).toContain("maxItems cap");
  });

  it("marks enumeration incomplete when maxPages stops before total_rows", async () => {
    const fetchMock = vi.fn().mockResolvedValue(response([{ image_digest: "sha256:a" }], 2));
    const client = createAnchoreClient(connection, { fetch: fetchMock });

    const out = await fetchAllImageTagSummaryPages(
      client,
      connection,
      new URLSearchParams(),
      { maxPages: 1, maxItems: 10 },
    );

    expect(out.enumerationIncomplete).toBe(true);
    expect(out.incompleteReason).toContain("maxPages cap");
  });

  it("fails closed without fetching when caps are non-finite", async () => {
    const fetchMock = vi.fn();
    const client = createAnchoreClient(connection, { fetch: fetchMock });

    const out = await fetchAllImageTagSummaryPages(
      client,
      connection,
      new URLSearchParams(),
      { maxPages: Number.POSITIVE_INFINITY, maxItems: Number.POSITIVE_INFINITY },
    );

    expect(out.enumerationIncomplete).toBe(true);
    expect(out.pagesFetched).toBe(0);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
