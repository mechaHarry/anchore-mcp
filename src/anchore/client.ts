import type { ResolvedProfile } from "../config/profiles.js";
import {
  AnchoreHttpError,
  AnchoreInvalidResponseError,
  AnchoreNetworkError,
  AnchoreTimeoutError,
  userMessageForHttpStatus,
} from "./errors.js";

export type AnchoreClientOptions = {
  /** Override fetch (tests). */
  fetch?: typeof fetch;
  /** Default timeout for each request (ms). No retries on timeout. */
  defaultTimeoutMs?: number;
};

function joinBaseAndPath(baseUrl: string, path: string): string {
  const base = baseUrl.endsWith("/") ? baseUrl.slice(0, -1) : baseUrl;
  const p = path.startsWith("/") ? path : `/${path}`;
  return `${base}${p}`;
}

function buildAuthHeaders(profile: ResolvedProfile): Headers {
  const headers = new Headers();
  const token = `${profile.username}:${profile.password}`;
  const basic = Buffer.from(token, "utf8").toString("base64");
  headers.set("Authorization", `Basic ${basic}`);
  headers.set("Accept", "application/json");
  if (profile.account) {
    headers.set("x-anchore-account", profile.account);
  }
  return headers;
}

export class AnchoreClient {
  private readonly fetchImpl: typeof fetch;
  private readonly defaultTimeoutMs: number;

  constructor(
    private readonly profile: ResolvedProfile,
    options: AnchoreClientOptions = {},
  ) {
    this.fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.defaultTimeoutMs = options.defaultTimeoutMs ?? 60_000;
  }

  /**
   * GET JSON from Anchore. Path is relative to the profile base URL (e.g. `/v1/images`).
   */
  async getJson<T>(path: string, init?: { timeoutMs?: number }): Promise<T> {
    const url = joinBaseAndPath(this.profile.baseUrl, path);
    const timeoutMs = init?.timeoutMs ?? this.defaultTimeoutMs;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    const headers = buildAuthHeaders(this.profile);

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
      if (text.length === 0) {
        return {} as T;
      }
      try {
        return JSON.parse(text) as T;
      } catch (e) {
        throw new AnchoreInvalidResponseError(
          "Anchore returned a non-JSON response for this endpoint.",
          { cause: e },
        );
      }
    } catch (e: unknown) {
      if (e instanceof AnchoreHttpError) {
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
  profile: ResolvedProfile,
  options?: AnchoreClientOptions,
): AnchoreClient {
  return new AnchoreClient(profile, options);
}
