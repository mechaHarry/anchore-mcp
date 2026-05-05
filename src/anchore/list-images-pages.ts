import type { ResolvedAnchoreConnection } from "../config/connection.js";
import { imagesListPath, type AnchoreApiVersion } from "./api-paths.js";
import type { AnchoreClient } from "./client.js";
import { extractImageListRows } from "./image-records.js";

export type ListImagesPageCaps = {
  /** Maximum HTTP requests for this list operation. */
  maxPages: number;
  /** Stop after collecting this many image rows (across pages). */
  maxItems: number;
};

export type FetchAllListImagesResult = {
  /** Merged JSON body in the same outer shape as a single-page list (`images`, `items`, or a root array). */
  mergedBody: unknown;
  pagesFetched: number;
  /** True when caps stopped the walk before the deployment indicated there was no further page. */
  enumerationIncomplete: boolean;
  incompleteReason?: string;
};

function detectWrapper(data: unknown): "images" | "items" | "array" {
  if (Array.isArray(data)) {
    return "array";
  }
  if (data !== null && typeof data === "object") {
    const o = data as Record<string, unknown>;
    if ("images" in o && Array.isArray(o.images)) {
      return "images";
    }
    if ("items" in o && Array.isArray(o.items)) {
      return "items";
    }
  }
  return "items";
}

function mergeRows(
  wrapper: "images" | "items" | "array",
  rows: unknown[],
): unknown {
  if (wrapper === "array") {
    return rows;
  }
  if (wrapper === "images") {
    return { images: rows };
  }
  return { items: rows };
}

function parseLinkNextUrl(linkHeader: string | null): string | null {
  if (linkHeader === null || linkHeader === undefined || linkHeader.trim() === "") {
    return null;
  }
  for (const part of linkHeader.split(",")) {
    const m = part.match(/<([^>]+)>\s*;\s*rel="next"/i);
    if (m) {
      return m[1].trim();
    }
  }
  return null;
}

function toAnchorePathOnly(baseUrl: string, href: string): string | null {
  try {
    const base = new URL(baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`);
    const next = new URL(href, base);
    if (next.origin !== base.origin) {
      return null;
    }
    return `${next.pathname}${next.search}`;
  } catch {
    return null;
  }
}

function nextPathFromJsonBody(
  data: unknown,
  baseUrl: string,
  version: AnchoreApiVersion,
  baseParams: URLSearchParams,
): string | null {
  if (data === null || typeof data !== "object") {
    return null;
  }
  const o = data as Record<string, unknown>;
  const next = o.next;
  if (typeof next === "string" && next.length > 0) {
    const p = toAnchorePathOnly(baseUrl, next);
    if (p !== null) {
      return p;
    }
  }
  const tokenKeys = ["next_page_token", "nextPageToken", "continuation_token", "page_token"] as const;
  for (const k of tokenKeys) {
    const v = o[k];
    if (typeof v === "string" && v.length > 0) {
      const p = new URLSearchParams(baseParams.toString());
      p.set("page_token", v);
      return imagesListPath(version, p);
    }
  }
  return null;
}

/**
 * Walk GET /v1|/v2/images with optional query params until no further page is indicated
 * or caps trigger enumerationIncomplete (R10).
 */
export async function fetchAllListImagesPages(
  client: AnchoreClient,
  connection: ResolvedAnchoreConnection,
  baseParams: URLSearchParams,
  caps: ListImagesPageCaps,
): Promise<FetchAllListImagesResult> {
  const version = connection.apiVersion;
  let path = imagesListPath(version, baseParams);
  const allRows: unknown[] = [];
  let wrapper: "images" | "items" | "array" | null = null;
  let pages = 0;
  let enumerationIncomplete: boolean;
  let incompleteReason: string | undefined;

  while (pages < caps.maxPages) {
    const { data, responseHeaders } = await client.getJsonWithByteLengthAndHeaders<unknown>(
      path,
    );
    pages += 1;

    if (wrapper === null) {
      wrapper = detectWrapper(data);
    }
    const pageRows = extractImageListRows(data);
    for (const r of pageRows) {
      if (allRows.length >= caps.maxItems) {
        enumerationIncomplete = true;
        incompleteReason = `Stopped after collecting ${caps.maxItems} image row(s) (maxItems cap).`;
        return {
          mergedBody: mergeRows(wrapper, allRows),
          pagesFetched: pages,
          enumerationIncomplete,
          incompleteReason,
        };
      }
      allRows.push(r);
    }

    const linkNext = parseLinkNextUrl(responseHeaders.get("link"));
    const linkPath =
      linkNext !== null ? toAnchorePathOnly(connection.baseUrl, linkNext) : null;
    const bodyNext = nextPathFromJsonBody(data, connection.baseUrl, version, baseParams);
    const nextPath = linkPath ?? bodyNext;

    if (nextPath === null || nextPath === path) {
      return {
        mergedBody: mergeRows(wrapper ?? "items", allRows),
        pagesFetched: pages,
        enumerationIncomplete: false,
      };
    }

    if (pages >= caps.maxPages) {
      enumerationIncomplete = true;
      incompleteReason = `Stopped after ${caps.maxPages} page request(s) (maxPages cap).`;
      return {
        mergedBody: mergeRows(wrapper ?? "items", allRows),
        pagesFetched: pages,
        enumerationIncomplete,
        incompleteReason,
      };
    }

    path = nextPath;
  }

  enumerationIncomplete = true;
  incompleteReason = `Stopped after ${caps.maxPages} page request(s) (maxPages cap).`;
  return {
    mergedBody: mergeRows(wrapper ?? "items", allRows),
    pagesFetched: pages,
    enumerationIncomplete,
    incompleteReason,
  };
}

/** Default caps for user-facing list (higher than internal resolution scans if needed). */
export const DEFAULT_LIST_IMAGES_CAPS: ListImagesPageCaps = {
  maxPages: 200,
  maxItems: 50_000,
};

/** Tighter caps for reference resolution walks (plan / R10). */
export const DEFAULT_RESOLUTION_LIST_CAPS: ListImagesPageCaps = {
  maxPages: 100,
  maxItems: 20_000,
};
