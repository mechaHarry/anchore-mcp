import type { ResolvedAnchoreConnection } from "../config/connection.js";
import {
  AnchoreHttpError,
  AnchoreInvalidResponseError,
  AnchoreNetworkError,
  AnchoreResponseTooLargeError,
  AnchoreTimeoutError,
  userMessageForHttpStatus,
} from "./errors.js";

export type AnchoreClientOptions = {
  /** Override fetch (tests). */
  fetch?: typeof fetch;
  /** Default timeout for each request (ms). No retries on timeout. */
  defaultTimeoutMs?: number;
};

export type GetJsonOptions = {
  timeoutMs?: number;
  /** If set, reject when the raw UTF-8 body exceeds this size (R15). */
  maxResponseBytes?: number;
};

function joinBaseAndPath(baseUrl: string, path: string): string {
  const base = baseUrl.endsWith("/") ? baseUrl.slice(0, -1) : baseUrl;
  const p = path.startsWith("/") ? path : `/${path}`;
  return `${base}${p}`;
}

function buildAuthHeaders(conn: ResolvedAnchoreConnection): Headers {
  const headers = new Headers();
  const token = `${conn.username}:${conn.password}`;
  const basic = Buffer.from(token, "utf8").toString("base64");
  headers.set("Authorization", `Basic ${basic}`);
  headers.set("Accept", "application/json");
  if (conn.account) {
    headers.set("x-anchore-account", conn.account);
  }
  return headers;
}

export class AnchoreClient {
  private readonly fetchImpl: typeof fetch;
  private readonly defaultTimeoutMs: number;

  constructor(
    private readonly connection: ResolvedAnchoreConnection,
    options: AnchoreClientOptions = {},
  ) {
    this.fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.defaultTimeoutMs = options.defaultTimeoutMs ?? 60_000;
  }

  /**
   * GET JSON from Anchore. Path must include the API version (e.g. `/v2/images`).
   */
  async getJson<T>(path: string, init?: GetJsonOptions): Promise<T> {
    const { data } = await this.getJsonWithByteLength<T>(path, init);
    return data;
  }

  /**
   * GET JSON and return UTF-8 byte length of the raw body (for R15 size metadata).
   */
  async getJsonWithByteLength<T>(
    path: string,
    init?: GetJsonOptions,
  ): Promise<{ data: T; byteLength: number }> {
    const url = joinBaseAndPath(this.connection.baseUrl, path);
    const timeoutMs = init?.timeoutMs ?? this.defaultTimeoutMs;
    const maxResponseBytes = init?.maxResponseBytes;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    const headers = buildAuthHeaders(this.connection);

    try {
      const res = await this.fetchImpl(url, {
        method: "GET",
        headers,
        signal: controller.signal,
      });

      if (!res.ok) {
        throw new AnchoreHttpError(res.status, userMessageForHttpStatus(res.status), {
          cause: undefined,
        });
      }

      const text = await res.text();
      const byteLength = Buffer.byteLength(text, "utf8");
      if (maxResponseBytes !== undefined && byteLength > maxResponseBytes) {
        throw new AnchoreResponseTooLargeError(byteLength, maxResponseBytes);
      }
      if (text.length === 0) {
        return { data: {} as T, byteLength: 0 };
      }
      try {
        return { data: JSON.parse(text) as T, byteLength };
      } catch (e) {
        throw new AnchoreInvalidResponseError(
          "Anchore returned a non-JSON response for this endpoint.",
          { cause: e },
        );
      }
    } catch (e: unknown) {
      if (
        e instanceof AnchoreHttpError ||
        e instanceof AnchoreInvalidResponseError ||
        e instanceof AnchoreResponseTooLargeError
      ) {
        throw e;
      }
      if (isAbortError(e)) {
        throw new AnchoreTimeoutError(timeoutMs, { cause: e });
      }
      if (e instanceof TypeError) {
        throw new AnchoreNetworkError(
          "Could not reach Anchore — check base URL, TLS, and network.",
          { cause: e },
        );
      }
      throw e;
    } finally {
      clearTimeout(timeout);
    }
  }
}

function isAbortError(e: unknown): boolean {
  if (e === null || e === undefined || typeof e !== "object") {
    return false;
  }
  const name = (e as { name?: string }).name;
  return name === "AbortError";
}

export function createAnchoreClient(
  connection: ResolvedAnchoreConnection,
  options?: AnchoreClientOptions,
): AnchoreClient {
  return new AnchoreClient(connection, options);
}
