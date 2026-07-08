import type { ResolvedAnchoreConnection } from "../config/connection.js";
import type { AnchoreApiVersion } from "./api-paths.js";
import { imageFullTagQueryKey, imagesListPath } from "./api-paths.js";
import type { AnchoreClientOptions } from "./client.js";
import { fetchOpenApiDocument } from "./openapi-fetch.js";

/**
 * When OpenAPI cannot enumerate query params (missing doc, empty get.parameters),
 * allow these common GET /v1|/v2/images keys. Deployment-specific params should appear
 * in openapi.json — if not, operators can request extending this fallback list.
 */
const COMMON_FALLBACK_LIST_IMAGES_QUERY_KEYS = [
  "vulnerability_id",
  "limit",
  "page",
  "page_size",
  "page_token",
  "name",
  "image_digest",
  "tag",
] as const;

export function getFallbackListImagesQueryKeys(
  version: AnchoreApiVersion,
): readonly string[] {
  return [imageFullTagQueryKey(version), ...COMMON_FALLBACK_LIST_IMAGES_QUERY_KEYS];
}

/** Backward-compatible v2 fallback export. Prefer getFallbackListImagesQueryKeys. */
export const FALLBACK_LIST_IMAGES_QUERY_KEYS =
  getFallbackListImagesQueryKeys("v2");

function listImagesOpenApiPath(version: AnchoreApiVersion): string {
  return version === "v1" ? "/v1/images" : "/v2/images";
}

/**
 * Collect `in: query` parameter names from a Path Item `get` operation (OpenAPI 3.x).
 * Skips `$ref` parameters without resolving components (MVP).
 */
export function extractListImagesQueryParameterNames(doc: unknown, pathKey: string): string[] {
  if (doc === null || typeof doc !== "object") {
    return [];
  }
  const paths = (doc as { paths?: Record<string, unknown> }).paths;
  if (paths === null || typeof paths !== "object") {
    return [];
  }
  const pathItem = paths[pathKey];
  if (pathItem === null || typeof pathItem !== "object") {
    return [];
  }
  const getOp = (pathItem as { get?: unknown }).get;
  if (getOp === null || typeof getOp !== "object") {
    return [];
  }
  const parameters = (getOp as { parameters?: unknown }).parameters;
  if (!Array.isArray(parameters)) {
    return [];
  }
  const names: string[] = [];
  for (const p of parameters) {
    if (p === null || typeof p !== "object") {
      continue;
    }
    const param = p as { $ref?: string; name?: string; in?: string };
    if (param.$ref !== undefined) {
      continue;
    }
    if (param.in === "query" && typeof param.name === "string" && param.name.length > 0) {
      names.push(param.name);
    }
  }
  return names;
}

/**
 * Allowed query keys: always includes {@link FALLBACK_LIST_IMAGES_QUERY_KEYS}, unioned with
 * `in: query` names from the deployment OpenAPI when the document parses.
 */
export async function getListImagesQueryParameterAllowlist(
  connection: ResolvedAnchoreConnection,
  options?: AnchoreClientOptions,
): Promise<Set<string>> {
  const base = new Set<string>(
    getFallbackListImagesQueryKeys(connection.apiVersion),
  );
  try {
    const doc = await fetchOpenApiDocument(connection, options);
    const pathKey = listImagesOpenApiPath(connection.apiVersion);
    const fromSpec = extractListImagesQueryParameterNames(doc, pathKey);
    for (const n of fromSpec) {
      base.add(n);
    }
  } catch {
    // OpenAPI fetch is best-effort; fallback keys still apply.
  }
  return base;
}

/** Path segment used for list images (for docs / debugging). */
export function listImagesPathForConnection(connection: ResolvedAnchoreConnection): string {
  return imagesListPath(connection.apiVersion, new URLSearchParams());
}

export const MAX_LIST_QUERY_KEYS = 32;
export const MAX_LIST_QUERY_VALUE_LEN = 4096;

export type ListImagesQueryInput = {
  fulltag?: string;
  vulnerability_id?: string;
  /** Optional extra query parameters (keys must be allowlisted). */
  list_query?: Record<string, string>;
};

/**
 * Build `URLSearchParams` for GET /v1|/v2/images. Public `fulltag` is translated to
 * the version's wire key (`fulltag` for v1, `full_tag` for v2); explicit filters
 * win over both aliases in `list_query`.
 */
export function mergeListImagesQueryParams(
  args: ListImagesQueryInput,
  allowlist: Set<string>,
  version: AnchoreApiVersion,
): { params: URLSearchParams; rejectedKeys: string[] } {
  const params = new URLSearchParams();
  const rejectedKeys: string[] = [];

  if (args.fulltag?.trim()) {
    params.set(imageFullTagQueryKey(version), args.fulltag.trim());
  }
  if (args.vulnerability_id?.trim()) {
    params.set("vulnerability_id", args.vulnerability_id.trim());
  }

  const raw = args.list_query;
  if (raw === undefined || typeof raw !== "object" || raw === null) {
    return { params, rejectedKeys };
  }

  const keys = Object.keys(raw).sort();
  let applied = 0;
  for (const k of keys) {
    if (applied >= MAX_LIST_QUERY_KEYS) {
      rejectedKeys.push(k);
      continue;
    }
    if (!allowlist.has(k)) {
      rejectedKeys.push(k);
      continue;
    }
    if ((k === "full_tag" || k === "fulltag") && args.fulltag?.trim()) {
      continue;
    }
    if (k === "vulnerability_id" && args.vulnerability_id?.trim()) {
      continue;
    }
    const v = raw[k];
    if (typeof v !== "string") {
      rejectedKeys.push(k);
      continue;
    }
    const t = v.trim();
    if (t.length > MAX_LIST_QUERY_VALUE_LEN) {
      rejectedKeys.push(k);
      continue;
    }
    if (t.length === 0) {
      continue;
    }
    params.set(k, t);
    applied += 1;
  }

  return { params, rejectedKeys };
}
