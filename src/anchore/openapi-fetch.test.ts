import { afterEach, describe, expect, it, vi } from "vitest";
import type { ResolvedAnchoreConnection } from "../config/connection.js";
import {
  clearOpenApiCacheForTests,
  fetchOpenApiDocument,
  invalidateOpenApiCache,
} from "./openapi-fetch.js";

function connection(apiVersion: "v1" | "v2" = "v2"): ResolvedAnchoreConnection {
  return {
    baseUrl: "https://ae.example.com",
    username: "_api_key",
    password: "tok",
    apiVersion,
  };
}

afterEach(() => {
  clearOpenApiCacheForTests();
  vi.restoreAllMocks();
});

describe("fetchOpenApiDocument", () => {
  it("GETs same-origin OpenAPI path for v2 and caches the document", async () => {
    const conn = connection("v2");
    const doc = { openapi: "3.0.0" };
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(doc), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const a = await fetchOpenApiDocument(conn, { fetch: fetchMock });
    const b = await fetchOpenApiDocument(conn, { fetch: fetchMock });

    expect(a).toEqual(doc);
    expect(b).toEqual(doc);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe("https://ae.example.com/v2/openapi.json");
  });

  it("uses /v1/openapi.json when apiVersion is v1", async () => {
    const conn = connection("v1");
    const fetchMock = vi.fn().mockResolvedValue(new Response("{}", { status: 200 }));
    await fetchOpenApiDocument(conn, { fetch: fetchMock });
    expect(fetchMock.mock.calls[0][0]).toBe("https://ae.example.com/v1/openapi.json");
  });

  it("refetches after invalidateOpenApiCache", async () => {
    const conn = connection();
    const fetchMock = vi.fn().mockImplementation(
      () => new Response('{"x":1}', { status: 200 }),
    );
    await fetchOpenApiDocument(conn, { fetch: fetchMock });
    invalidateOpenApiCache(conn);
    await fetchOpenApiDocument(conn, { fetch: fetchMock });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("does not follow OpenAPI redirects", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response("", {
        status: 302,
        headers: { Location: "https://evil.example/openapi.json" },
      }),
    );

    await expect(
      fetchOpenApiDocument(connection("v1"), { fetch: fetchMock }),
    ).rejects.toMatchObject({ status: 302 });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe("https://ae.example.com/v1/openapi.json");
    expect(fetchMock.mock.calls[0][1]).toMatchObject({ redirect: "manual" });
  });
});
