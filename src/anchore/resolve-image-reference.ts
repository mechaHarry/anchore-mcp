import type { ResolvedAnchoreConnection } from "../config/connection.js";
import { createAnchoreClient, type AnchoreClientOptions } from "./client.js";
import {
  DEFAULT_RESOLUTION_LIST_CAPS,
  fetchAllListImagesPages,
  type ListImagesPageCaps,
} from "./list-images-pages.js";
import {
  digestFromImageRow,
  extractImageListRows,
  validateFullImageReference,
} from "./image-records.js";

const MAX_DISAMBIGUATION_CANDIDATES = 50;

export type ResolveCandidate = {
  digest: string;
  /** Best-effort tag strings from row metadata when present. */
  tags?: string[];
};

export type ResolveImageReferenceResult =
  | { kind: "ok"; digest: string }
  | { kind: "no_match" }
  | {
      kind: "disambiguate";
      candidates: ResolveCandidate[];
      disambiguation_truncated: boolean;
    }
  | { kind: "enumeration_incomplete"; reason: string }
  | { kind: "upstream_error"; message: string };

function tagHintsFromRow(row: unknown): string[] | undefined {
  if (row === null || typeof row !== "object") {
    return undefined;
  }
  const o = row as Record<string, unknown>;
  const tags: string[] = [];
  const fulltag = o.fulltag ?? o.full_tag ?? o.tag;
  if (typeof fulltag === "string" && fulltag.trim().length > 0) {
    tags.push(fulltag.trim());
  }
  if (Array.isArray(o.tags)) {
    for (const t of o.tags) {
      if (typeof t === "string" && t.trim().length > 0) {
        tags.push(t.trim());
      }
    }
  }
  return tags.length > 0 ? tags : undefined;
}

/**
 * Resolve a full image reference to a single digest using GET /images?full_tag=… (paginated).
 */
export async function resolveImageReference(
  connection: ResolvedAnchoreConnection,
  imageReference: string,
  options?: AnchoreClientOptions & {
    listCaps?: ListImagesPageCaps;
  },
): Promise<ResolveImageReferenceResult> {
  const validated = validateFullImageReference(imageReference);
  if (!validated.ok) {
    return { kind: "upstream_error", message: validated.message };
  }

  const params = new URLSearchParams();
  params.set("full_tag", imageReference.trim());

  const { listCaps: capsOverride, ...clientOptions } = options ?? {};
  const client = createAnchoreClient(connection, clientOptions);
  const caps = capsOverride ?? DEFAULT_RESOLUTION_LIST_CAPS;

  let merged: unknown;
  let pagesFetched: number;
  let enumerationIncomplete: boolean;
  let incompleteReason: string | undefined;
  try {
    const out = await fetchAllListImagesPages(client, connection, params, caps);
    merged = out.mergedBody;
    pagesFetched = out.pagesFetched;
    enumerationIncomplete = out.enumerationIncomplete;
    incompleteReason = out.incompleteReason;
  } catch (e) {
    const msg =
      e instanceof Error ? e.message : "Failed to list images while resolving reference.";
    return { kind: "upstream_error", message: msg };
  }

  if (enumerationIncomplete) {
    return {
      kind: "enumeration_incomplete",
      reason:
        incompleteReason ??
        `Image list enumeration incomplete after ${pagesFetched} page(s). Narrow full_tag or raise caps.`,
    };
  }

  const rows = extractImageListRows(merged);
  const byDigest = new Map<string, ResolveCandidate>();

  for (const row of rows) {
    const digest = digestFromImageRow(row);
    if (digest === undefined) {
      continue;
    }
    const existing = byDigest.get(digest);
    const hints = tagHintsFromRow(row);
    if (existing === undefined) {
      byDigest.set(digest, { digest, ...(hints !== undefined ? { tags: hints } : {}) });
    } else if (hints !== undefined) {
      const mergedTags = new Set([...(existing.tags ?? []), ...hints]);
      byDigest.set(digest, {
        digest,
        tags: [...mergedTags],
      });
    }
  }

  const unique = [...byDigest.values()];
  if (unique.length === 0) {
    return { kind: "no_match" };
  }
  if (unique.length === 1) {
    return { kind: "ok", digest: unique[0].digest };
  }

  const sorted = unique.sort((a, b) => a.digest.localeCompare(b.digest));
  let disambiguation_truncated = false;
  let candidates = sorted;
  if (sorted.length > MAX_DISAMBIGUATION_CANDIDATES) {
    candidates = sorted.slice(0, MAX_DISAMBIGUATION_CANDIDATES);
    disambiguation_truncated = true;
  }

  return {
    kind: "disambiguate",
    candidates,
    disambiguation_truncated,
  };
}
