import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createAnchoreClient } from "./client.js";
import {
  AnchoreHttpError,
  AnchoreInvalidResponseError,
  AnchoreNetworkError,
} from "./errors.js";

const connection = {
  baseUrl: "https://anchore.example.com",
  username: "_api_key" as const,
  password: "SUPER_SECRET_TOKEN",
  account: "test-account",
  apiVersion: "v2" as const,
};

describe("AnchoreClient", () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("GET returns parsed JSON on 200", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ images: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const client = createAnchoreClient(connection, { fetch: fetchMock });
    const data = await client.getJson<{ images: unknown[] }>("/v1/images");
    expect(data.images).toEqual([]);

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as [
      string,
      RequestInit | undefined,
    ];
    expect(url).toBe("https://anchore.example.com/v1/images");
    const headers = init?.headers as Headers;
    expect(headers.get("Authorization")).toMatch(/^Basic\s+/);
    expect(headers.get("Accept")).toBe("application/json");
    expect(headers.get("x-anchore-account")).toBe("test-account");
  });

  it("401 produces AnchoreHttpError with safe message (no token in message)", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(new Response("", { status: 401 }));
    const client = createAnchoreClient(connection, { fetch: fetchMock });
    try {
      await client.getJson("/v1/images");
      expect.fail("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(AnchoreHttpError);
      const err = e as AnchoreHttpError;
      expect(err.status).toBe(401);
      expect(err.userMessage).toMatch(/denied/i);
      expect(err.userMessage).not.toContain("SUPER_SECRET");
      expect(err.userMessage).not.toContain("Basic ");
    }
  });

  it("403 uses safe message", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(new Response("", { status: 403 }));
    const client = createAnchoreClient(connection, { fetch: fetchMock });
    await expect(client.getJson("/x")).rejects.toMatchObject({
      status: 403,
      userMessage: expect.stringMatching(/denied/i),
    });
  });

  it("timeout maps to AnchoreTimeoutError (no retries)", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn(
      (_input: string | URL | Request, init?: RequestInit) => {
        return new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            reject(new DOMException("Aborted", "AbortError"));
          });
        });
      },
    );
    const client = createAnchoreClient(connection, {
      fetch: fetchMock,
      defaultTimeoutMs: 100,
    });
    const p = client.getJson("/v1/slow");
    const assertion = expect(p).rejects.toMatchObject({
      name: "AnchoreTimeoutError",
      timeoutMs: 100,
    });
    await vi.advanceTimersByTimeAsync(150);
    await assertion;
    vi.useRealTimers();
  });

  it("TypeError from fetch maps to AnchoreNetworkError", async () => {
    const fetchMock = vi
      .fn()
      .mockRejectedValue(new TypeError("fetch failed"));
    const client = createAnchoreClient(connection, { fetch: fetchMock });
    await expect(client.getJson("/v1/images")).rejects.toBeInstanceOf(
      AnchoreNetworkError,
    );
  });

  it("invalid JSON on 200 maps to AnchoreInvalidResponseError", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(new Response("not-json", { status: 200 }));
    const client = createAnchoreClient(connection, { fetch: fetchMock });
    await expect(client.getJson("/x")).rejects.toBeInstanceOf(
      AnchoreInvalidResponseError,
    );
  });

  it("empty 200 body yields empty object", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("", { status: 200 }));
    const client = createAnchoreClient(connection, { fetch: fetchMock });
    const data = await client.getJson<Record<string, never>>("/x");
    expect(data).toEqual({});
  });

  it("omits x-anchore-account when connection has no account", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response("{}", { status: 200 }),
    );
    const client = createAnchoreClient(
      {
        baseUrl: "https://anchore.example.com",
        username: "_api_key",
        password: "SUPER_SECRET_TOKEN",
        apiVersion: "v2",
      },
      { fetch: fetchMock },
    );
    await client.getJson("/x");
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    const headers = init.headers as Headers;
    expect(headers.get("x-anchore-account")).toBeNull();
  });
});
