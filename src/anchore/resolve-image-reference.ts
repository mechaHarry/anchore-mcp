import type { ResolvedAnchoreConnection } from "../config/connection.js";
import { imageFullTagQueryKey } from "./api-paths.js";
import { createAnchoreClient, type AnchoreClientOptions } from "./client.js";
import {
  DEFAULT_RESOLUTION_LIST_CAPS,
  fetchAllListImagesPages,
  type ListImagesPageCaps,
} from "./list-images-pages.js";
import {
  digestFromImageRow,
  extractImageListRows,
  fullImageReferencesFromRow,
  validateFullImageReference,
} from "./image-records.js";

const MAX_DISAMBIGUATION_CANDIDATES = 50;
const MAX_TAG_HINTS_PER_DIGEST = 8;
const MAX_TOTAL_DISAMBIGUATION_TAG_HINTS = 64;
const EVIDENCE_INCOMPLETE_REASON =
  "Image reference evidence exceeded safety limits.";

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

/**
 * Resolve a full image reference using the API version's full-tag query key (paginated).
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

  const requestedReference = imageReference.trim();
  const params = new URLSearchParams();
  params.set(imageFullTagQueryKey(connection.apiVersion), requestedReference);

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
    const queryKey = imageFullTagQueryKey(connection.apiVersion);
    const baseReason =
      incompleteReason ??
      `Image list enumeration incomplete after ${pagesFetched} page(s).`;
    return {
      kind: "enumeration_incomplete",
      reason: `${baseReason} Narrow ${queryKey} or raise caps.`,
    };
  }

  const rows = extractImageListRows(merged);
  const byDigest = new Map<string, ResolveCandidate>();

  for (const row of rows) {
    const evidence = fullImageReferencesFromRow(row);
    if (evidence.evidenceIncomplete) {
      return {
        kind: "enumeration_incomplete",
        reason: EVIDENCE_INCOMPLETE_REASON,
      };
    }
    const references = evidence.references;
    if (!references.includes(requestedReference)) {
      continue;
    }
    const digest = digestFromImageRow(row);
    if (digest === undefined) {
      continue;
    }
    const existing = byDigest.get(digest);
    const hints = [
      requestedReference,
      ...references.filter((reference) => reference !== requestedReference),
    ].slice(0, MAX_TAG_HINTS_PER_DIGEST);
    if (existing === undefined) {
      byDigest.set(digest, { digest, ...(hints.length > 0 ? { tags: hints } : {}) });
    } else if (hints.length > 0) {
      const mergedTags = new Set([
        requestedReference,
        ...(existing.tags ?? []).filter((tag) => tag !== requestedReference),
        ...hints.filter((tag) => tag !== requestedReference),
      ]);
      byDigest.set(digest, {
        digest,
        tags: [...mergedTags].slice(0, MAX_TAG_HINTS_PER_DIGEST),
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

  let remainingOptionalTagHints =
    MAX_TOTAL_DISAMBIGUATION_TAG_HINTS - candidates.length;
  candidates = candidates.map((candidate) => {
    const optionalTags = (candidate.tags ?? [])
      .filter((tag) => tag !== requestedReference)
      .slice(
        0,
        Math.min(
          MAX_TAG_HINTS_PER_DIGEST - 1,
          remainingOptionalTagHints,
        ),
      );
    remainingOptionalTagHints -= optionalTags.length;
    return {
      digest: candidate.digest,
      tags: [requestedReference, ...optionalTags],
    };
  });

  return {
    kind: "disambiguate",
    candidates,
    disambiguation_truncated,
  };
}
