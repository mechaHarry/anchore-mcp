import type { ResolvedAnchoreConnection } from "../config/connection.js";
import {
  AnchoreHttpError,
  AnchoreInvalidResponseError,
  AnchoreNetworkError,
  AnchoreResponseTooLargeError,
  AnchoreTimeoutError,
  userMessageForHttpStatus,
} from "./errors.js";
import {
  backoffDelayMs,
  getGetRetryPolicyFromEnv,
  isTransientHttpStatus,
  type GetRetryPolicy,
  retryAfterDelayMs,
  shouldRetryGet,
  sleepMs,
} from "./retry-policy.js";

export type AnchoreClientOptions = {
  /** Override fetch (tests). */
  fetch?: typeof fetch;
  /** Default timeout for each request (ms). No retries on timeout. */
  defaultTimeoutMs?: number;
  /**
   * Retry policy for idempotent GETs. Defaults to env (`ANCHORE_HTTP_*`) via
   * `getGetRetryPolicyFromEnv()` when omitted.
   */
  getRetryPolicy?: GetRetryPolicy;
};

export type GetJsonOptions = {
  timeoutMs?: number;
  /** If set, reject when the raw UTF-8 body exceeds this size (R15). */
  maxResponseBytes?: number;
  /** Override fetch redirect handling for this request (OpenAPI uses `manual`). */
  redirect?: NonNullable<RequestInit["redirect"]>;
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
  private readonly getRetryPolicy: GetRetryPolicy;

  constructor(
    private readonly connection: ResolvedAnchoreConnection,
    options: AnchoreClientOptions = {},
  ) {
    this.fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.defaultTimeoutMs = options.defaultTimeoutMs ?? 60_000;
    this.getRetryPolicy = options.getRetryPolicy ?? getGetRetryPolicyFromEnv();
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
    const { data, byteLength } = await this.getJsonWithByteLengthAndHeaders<T>(
      path,
      init,
    );
    return { data, byteLength };
  }

  /**
   * GET JSON with response headers (e.g. `Link` for paginated list routes).
   */
  async getJsonWithByteLengthAndHeaders<T>(
    path: string,
    init?: GetJsonOptions,
  ): Promise<{ data: T; byteLength: number; responseHeaders: Headers }> {
    const policy = this.getRetryPolicy;
    const maxAttempts = policy.maxRetries + 1;
    const url = joinBaseAndPath(this.connection.baseUrl, path);
    const timeoutMs = init?.timeoutMs ?? this.defaultTimeoutMs;
    const maxResponseBytes = init?.maxResponseBytes;
    const redirect = init?.redirect;
    const headers = buildAuthHeaders(this.connection);

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), timeoutMs);

      try {
        const requestInit: RequestInit = {
          method: "GET",
          headers,
          signal: controller.signal,
        };
        if (redirect !== undefined) {
          requestInit.redirect = redirect;
        }
        const res = await this.fetchImpl(url, requestInit);

        if (!res.ok) {
          const status = res.status;
          if (
            attempt < maxAttempts - 1 &&
            isTransientHttpStatus(status)
          ) {
            const ra =
              status === 429 ? retryAfterDelayMs(res.headers) : undefined;
            await sleepMs(backoffDelayMs(attempt, policy, ra));
            continue;
          }
          throw new AnchoreHttpError(status, userMessageForHttpStatus(status), {
            cause: undefined,
          });
        }

        const text = await res.text();
        const byteLength = Buffer.byteLength(text, "utf8");
        if (maxResponseBytes !== undefined && byteLength > maxResponseBytes) {
          throw new AnchoreResponseTooLargeError(byteLength, maxResponseBytes);
        }
        if (text.length === 0) {
          return { data: {} as T, byteLength: 0, responseHeaders: res.headers };
        }
        try {
          return {
            data: JSON.parse(text) as T,
            byteLength,
            responseHeaders: res.headers,
          };
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
          const netErr = new AnchoreNetworkError(
            "Could not reach Anchore — check base URL, TLS, and network.",
            { cause: e },
          );
          if (shouldRetryGet(netErr, attempt, policy)) {
            await sleepMs(backoffDelayMs(attempt, policy));
            continue;
          }
          throw netErr;
        }
        throw e;
      } finally {
        clearTimeout(timeout);
      }
    }

    throw new Error("AnchoreClient: GET retry loop exited without result");
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
