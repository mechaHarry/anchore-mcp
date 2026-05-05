import type { ResolvedAnchoreConnection } from "../config/connection.js";
import type { AnchoreApiVersion } from "./api-paths.js";
import { createAnchoreClient, type AnchoreClientOptions } from "./client.js";

const DEFAULT_TTL_MS = 10 * 60 * 1000;
const MAX_OPENAPI_BYTES = 6_000_000;

type CacheEntry = {
  doc: unknown;
  expiresAt: number;
};

const cache = new Map<string, CacheEntry>();

function cacheKey(baseUrl: string, apiVersion: AnchoreApiVersion): string {
  return `${baseUrl}::${apiVersion}`;
}

export function openApiPathForVersion(apiVersion: AnchoreApiVersion): string {
  return apiVersion === "v1" ? "/v1/openapi.json" : "/v2/openapi.json";
}

/**
 * Fetch deployment OpenAPI JSON (same origin as ANCHORE_URL). Cached in-memory with TTL.
 * Does not log the body to stderr.
 */
export async function fetchOpenApiDocument(
  connection: ResolvedAnchoreConnection,
  options?: AnchoreClientOptions & { ttlMs?: number },
): Promise<unknown> {
  const ttlMs = options?.ttlMs ?? DEFAULT_TTL_MS;
  const key = cacheKey(connection.baseUrl, connection.apiVersion);
  const now = Date.now();
  const hit = cache.get(key);
  if (hit !== undefined && hit.expiresAt > now) {
    return hit.doc;
  }

  const clientOptions = { ...options };
  delete (clientOptions as { ttlMs?: number }).ttlMs;
  const client = createAnchoreClient(connection, clientOptions);
  const path = openApiPathForVersion(connection.apiVersion);
  const doc = await client.getJson<unknown>(path, {
    maxResponseBytes: MAX_OPENAPI_BYTES,
  });
  cache.set(key, { doc, expiresAt: now + ttlMs });
  return doc;
}

export function invalidateOpenApiCache(connection: ResolvedAnchoreConnection): void {
  cache.delete(cacheKey(connection.baseUrl, connection.apiVersion));
}

/** Test hook: clear all cached OpenAPI docs. */
export function clearOpenApiCacheForTests(): void {
  cache.clear();
}
