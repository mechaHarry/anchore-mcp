import type { ResolvedAnchoreConnection } from "../config/connection.js";
import { imageFullTagQueryKey } from "./api-paths.js";
import { createAnchoreClient, type AnchoreClientOptions } from "./client.js";
import {
  digestFromImageRow,
  extractImageListRows,
  validateFullImageReference,
} from "./image-records.js";
import {
  DEFAULT_RESOLUTION_LIST_CAPS,
  fetchAllListImagesPages,
  type ListImagesPageCaps,
} from "./list-images-pages.js";
import { fetchAllImageTagSummaryPages } from "./image-tag-summary-pages.js";

export type PolicyBlockingImageLocator = {
  image_digest?: string;
  image_reference?: string;
  image_registry?: string;
  image_repository?: string;
};

type RepositoryLocator = {
  registry: string;
  repository: string;
};

export type SelectedImage = {
  digest: string;
  reference?: string;
  repository?: string;
  analysisTimestamp?: string;
};

export type ImageSelectionError = {
  ok: false;
  status: "image_selection_error";
  message: string;
  messageSource: "selector" | "backend";
};

export type ImageSelectionResult =
  | { ok: true; selectedImage: SelectedImage }
  | ImageSelectionError;

type ImageSelectionOptions = AnchoreClientOptions & {
  /** Test/operator override; defaults remain deliberately bounded. */
  listCaps?: ListImagesPageCaps;
};

type TimestampedCandidate = SelectedImage & {
  parsedTimestamp: number;
};

const REFERENCE_KEYS = [
  "fulltag",
  "full_tag",
  "tag",
  "image_tag",
  "imageTag",
] as const;

const IMAGE_DETAIL_KEYS = [
  "image_detail",
  "imageDetail",
  "image_details",
  "imageDetails",
] as const;

const TIMESTAMP_KEYS = [
  "analyzed_at",
  "analyzedAt",
  "analysis_timestamp",
  "analysisTimestamp",
  "last_updated",
  "lastUpdated",
  "created_at",
  "createdAt",
] as const;

// Analysis timestamps beyond year 2286 are not credible epoch seconds; larger
// magnitudes are interpreted as epoch milliseconds. This also supports legacy
// millisecond values before the common 1e12 heuristic boundary.
const MAX_PLAUSIBLE_EPOCH_SECONDS = 10_000_000_000;
const UNPROVEN_NEWEST_IMAGE_MESSAGE =
  "Cannot prove newest image because a matching digest-bearing row lacked a reliable analysis timestamp.";

function imageSelectionError(message: string): ImageSelectionError {
  return {
    ok: false,
    status: "image_selection_error",
    message,
    messageSource: "selector",
  };
}

function backendImageSelectionError(message: string): ImageSelectionError {
  return {
    ok: false,
    status: "image_selection_error",
    message,
    messageSource: "backend",
  };
}

function stringField(row: Record<string, unknown>, key: string): string | undefined {
  const value = row[key];
  return typeof value === "string" && value.trim().length > 0
    ? value.trim()
    : undefined;
}

function stringFields(row: Record<string, unknown>, keys: readonly string[]): string[] {
  const values: string[] = [];
  for (const key of keys) {
    const value = stringField(row, key);
    if (value !== undefined) {
      values.push(value);
    }
  }
  return values;
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values)];
}

function imageDetailRows(row: Record<string, unknown>): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  for (const key of IMAGE_DETAIL_KEYS) {
    const value = row[key];
    const values = Array.isArray(value) ? value : [value];
    for (const item of values) {
      if (item !== null && typeof item === "object") {
        out.push(item as Record<string, unknown>);
      }
    }
  }
  return out;
}

function derivedFullTagFromDetail(detail: Record<string, unknown>): string | undefined {
  const registry = stringField(detail, "registry");
  const repo = stringField(detail, "repo") ?? stringField(detail, "repository");
  const tag = stringField(detail, "tag");
  if (registry === undefined || repo === undefined || tag === undefined) {
    return undefined;
  }
  return `${registry}/${repo}:${tag}`;
}

function detailReferences(detail: Record<string, unknown>): string[] {
  const values = stringFields(detail, [
    "fulltag",
    "full_tag",
    "image_tag",
    "imageTag",
  ]);
  const derived = derivedFullTagFromDetail(detail);
  if (derived !== undefined) {
    values.push(derived);
  }
  return uniqueStrings(values);
}

function referencesFromRow(row: Record<string, unknown>): string[] {
  const values = stringFields(row, REFERENCE_KEYS);
  for (const detail of imageDetailRows(row)) {
    values.push(...detailReferences(detail));
  }
  return uniqueStrings(values);
}

function timestampFromRow(
  row: Record<string, unknown>,
): { value: string; parsed: number } | undefined {
  for (const key of TIMESTAMP_KEYS) {
    const raw = row[key];
    if (typeof raw === "number" && Number.isFinite(raw)) {
      const milliseconds =
        Math.abs(raw) <= MAX_PLAUSIBLE_EPOCH_SECONDS ? raw * 1_000 : raw;
      const date = new Date(milliseconds);
      const parsed = date.getTime();
      if (Number.isFinite(parsed)) {
        return { value: date.toISOString(), parsed };
      }
    }
    if (typeof raw === "string" && raw.trim().length > 0) {
      const value = raw.trim();
      const parsed = Date.parse(value);
      if (Number.isFinite(parsed)) {
        return { value: new Date(parsed).toISOString(), parsed };
      }
    }
  }
  return undefined;
}

function stripTagFromReference(reference: string): string | undefined {
  const trimmed = reference.trim();
  const lastSlash = trimmed.lastIndexOf("/");
  const lastColon = trimmed.lastIndexOf(":");
  if (lastSlash < 0 || lastColon <= lastSlash + 1 || lastColon === trimmed.length - 1) {
    return undefined;
  }
  return trimmed.slice(0, lastColon);
}

function validateRegistry(
  registry: string,
): { ok: true; value: string } | { ok: false; message: string } {
  // eslint-disable-next-line no-control-regex -- reject ASCII control chars before trimming
  if (/[\x00-\x1f\x7f]/.test(registry)) {
    return { ok: false, message: "image_registry contains invalid control characters." };
  }
  const trimmed = registry.trim();
  if (trimmed.length === 0) {
    return { ok: false, message: "image_registry is empty." };
  }
  if (trimmed.length > 1024) {
    return { ok: false, message: "image_registry is too long." };
  }
  if (trimmed.includes("/")) {
    return { ok: false, message: "image_registry must not contain '/'." };
  }
  return { ok: true, value: trimmed };
}

function validateRepository(
  repository: string,
): { ok: true; value: string } | { ok: false; message: string } {
  // eslint-disable-next-line no-control-regex -- reject ASCII control chars before trimming
  if (/[\x00-\x1f\x7f]/.test(repository)) {
    return { ok: false, message: "image_repository contains invalid control characters." };
  }
  const trimmed = repository.trim();
  if (trimmed.length === 0) {
    return { ok: false, message: "image_repository is empty." };
  }
  if (trimmed.length > 1024) {
    return { ok: false, message: "image_repository is too long." };
  }
  const lastSlash = trimmed.lastIndexOf("/");
  if (trimmed.startsWith("/") || trimmed.endsWith("/")) {
    return { ok: false, message: "image_repository must not begin or end with '/'." };
  }
  const lastColon = trimmed.lastIndexOf(":");
  if (lastColon > lastSlash) {
    return { ok: false, message: "image_repository must not include an image tag." };
  }
  return { ok: true, value: trimmed };
}

function locatorFromReference(reference: string): RepositoryLocator | undefined {
  const qualifiedRepository = stripTagFromReference(reference);
  if (qualifiedRepository === undefined) {
    return undefined;
  }
  const firstSlash = qualifiedRepository.indexOf("/");
  if (firstSlash <= 0 || firstSlash === qualifiedRepository.length - 1) {
    return undefined;
  }
  return {
    registry: qualifiedRepository.slice(0, firstSlash),
    repository: qualifiedRepository.slice(firstSlash + 1),
  };
}

function sameRepositoryLocator(a: RepositoryLocator, b: RepositoryLocator): boolean {
  return a.registry === b.registry && a.repository === b.repository;
}

function referenceMatchesLocator(reference: string, locator: RepositoryLocator): boolean {
  const candidate = locatorFromReference(reference);
  return candidate !== undefined && sameRepositoryLocator(candidate, locator);
}

function selectNewest(candidates: TimestampedCandidate[]): ImageSelectionResult {
  if (candidates.length === 0) {
    return imageSelectionError("No matching image row had both a digest and a reliable analysis timestamp.");
  }

  const sorted = [...candidates].sort((a, b) => b.parsedTimestamp - a.parsedTimestamp);
  const newest = sorted[0];
  const tiedDigests = new Set(
    sorted
      .filter((candidate) => candidate.parsedTimestamp === newest.parsedTimestamp)
      .map((candidate) => candidate.digest),
  );

  if (tiedDigests.size > 1) {
    return imageSelectionError(
      `Newest analyzed image is ambiguous: ${tiedDigests.size} digests share timestamp ${newest.analysisTimestamp ?? "unknown"}.`,
    );
  }

  const selectedImage: SelectedImage = {
    digest: newest.digest,
    ...(newest.reference !== undefined ? { reference: newest.reference } : {}),
    ...(newest.repository !== undefined ? { repository: newest.repository } : {}),
    ...(newest.analysisTimestamp !== undefined
      ? { analysisTimestamp: newest.analysisTimestamp }
      : {}),
  };
  return { ok: true, selectedImage };
}

async function listImages(
  params: URLSearchParams,
  connection: ResolvedAnchoreConnection,
  options?: ImageSelectionOptions,
): Promise<ImageSelectionError | unknown[]> {
  const { listCaps, ...clientOptions } = options ?? {};
  const client = createAnchoreClient(connection, clientOptions);
  try {
    const out = await fetchAllListImagesPages(
      client,
      connection,
      params,
      listCaps ?? DEFAULT_RESOLUTION_LIST_CAPS,
    );
    if (out.enumerationIncomplete) {
      return imageSelectionError(
        out.incompleteReason ??
          `Image list enumeration incomplete after ${out.pagesFetched} page(s).`,
      );
    }
    return extractImageListRows(out.mergedBody);
  } catch (e) {
    const message =
      e instanceof Error ? e.message : "Failed to list images for image selection.";
    return backendImageSelectionError(message);
  }
}

async function listImageTagSummaries(
  params: URLSearchParams,
  connection: ResolvedAnchoreConnection,
  options?: ImageSelectionOptions,
): Promise<ImageSelectionError | unknown[]> {
  const { listCaps, ...clientOptions } = options ?? {};
  const client = createAnchoreClient(connection, clientOptions);
  try {
    const out = await fetchAllImageTagSummaryPages(
      client,
      connection,
      params,
      listCaps ?? DEFAULT_RESOLUTION_LIST_CAPS,
    );
    if (out.enumerationIncomplete) {
      return imageSelectionError(
        out.incompleteReason ??
          `Image tag summary enumeration incomplete after ${out.pagesFetched} page(s).`,
      );
    }
    return out.rows;
  } catch (e) {
    const message =
      e instanceof Error ? e.message : "Failed to list image tag summaries for image selection.";
    return backendImageSelectionError(message);
  }
}

async function selectByReference(
  imageReference: string,
  connection: ResolvedAnchoreConnection,
  options?: ImageSelectionOptions,
): Promise<ImageSelectionResult> {
  const validated = validateFullImageReference(imageReference);
  if (!validated.ok) {
    return imageSelectionError(validated.message);
  }

  const reference = imageReference.trim();
  const params = new URLSearchParams();
  params.set(imageFullTagQueryKey(connection.apiVersion), reference);

  const rows = await listImages(params, connection, options);
  if (!Array.isArray(rows)) {
    return rows;
  }

  const repository = stripTagFromReference(reference);
  const candidates: TimestampedCandidate[] = [];
  for (const row of rows) {
    if (row === null || typeof row !== "object") {
      continue;
    }
    const objectRow = row as Record<string, unknown>;
    if (!referencesFromRow(objectRow).includes(reference)) {
      continue;
    }
    const digest = digestFromImageRow(objectRow);
    // A row without a digest cannot be selected and therefore cannot affect newest-digest proof.
    if (digest === undefined) {
      continue;
    }
    const timestamp = timestampFromRow(objectRow);
    if (timestamp === undefined) {
      return imageSelectionError(UNPROVEN_NEWEST_IMAGE_MESSAGE);
    }
    candidates.push({
      digest,
      reference,
      ...(repository !== undefined ? { repository } : {}),
      analysisTimestamp: timestamp.value,
      parsedTimestamp: timestamp.parsed,
    });
  }

  return selectNewest(candidates);
}

async function selectByRepository(
  imageRegistry: string,
  imageRepository: string,
  connection: ResolvedAnchoreConnection,
  options?: ImageSelectionOptions,
): Promise<ImageSelectionResult> {
  const validatedRegistry = validateRegistry(imageRegistry);
  if (!validatedRegistry.ok) {
    return imageSelectionError(validatedRegistry.message);
  }
  const validatedRepository = validateRepository(imageRepository);
  if (!validatedRepository.ok) {
    return imageSelectionError(validatedRepository.message);
  }
  const locator: RepositoryLocator = {
    registry: validatedRegistry.value,
    repository: validatedRepository.value,
  };
  const qualifiedRepository = `${locator.registry}/${locator.repository}`;

  const params = new URLSearchParams();
  params.set("registry", locator.registry);
  params.set("repository", locator.repository);
  params.set("analysis_status", "analyzed");

  const rows = await listImageTagSummaries(params, connection, options);
  if (!Array.isArray(rows)) {
    return rows;
  }

  const candidates: TimestampedCandidate[] = [];
  for (const row of rows) {
    if (row === null || typeof row !== "object") {
      continue;
    }
    const objectRow = row as Record<string, unknown>;
    const reference = stringField(objectRow, "full_tag");
    if (reference === undefined || !referenceMatchesLocator(reference, locator)) {
      continue;
    }
    const digest = digestFromImageRow(objectRow);
    // A row without a digest cannot be selected and therefore cannot affect newest-digest proof.
    if (digest === undefined) {
      continue;
    }
    const timestamp = timestampFromRow(objectRow);
    if (timestamp === undefined) {
      return imageSelectionError(UNPROVEN_NEWEST_IMAGE_MESSAGE);
    }
    candidates.push({
      digest,
      reference,
      repository: qualifiedRepository,
      analysisTimestamp: timestamp.value,
      parsedTimestamp: timestamp.parsed,
    });
  }

  return selectNewest(candidates);
}

export async function selectImageForPolicyBlockingReport(
  args: PolicyBlockingImageLocator,
  connection: ResolvedAnchoreConnection,
  options?: ImageSelectionOptions,
): Promise<ImageSelectionResult> {
  const hasDigest = args.image_digest !== undefined;
  const hasReference = args.image_reference !== undefined;
  const hasRegistry = args.image_registry !== undefined;
  const hasRepository = args.image_repository !== undefined;
  const hasComponentPair = hasRegistry && hasRepository;

  if (hasRegistry !== hasRepository) {
    return imageSelectionError(
      "Supply image_registry and image_repository together.",
    );
  }
  const locatorCount = Number(hasDigest) + Number(hasReference) + Number(hasComponentPair);
  if (locatorCount !== 1) {
    return imageSelectionError(
      "Supply exactly one of image_digest, image_reference, or the image_registry and image_repository pair.",
    );
  }

  if (hasDigest) {
    const digest = args.image_digest?.trim() ?? "";
    if (digest.length === 0) {
      return imageSelectionError("image_digest is empty.");
    }
    return { ok: true, selectedImage: { digest } };
  }
  if (hasReference) {
    return selectByReference(args.image_reference ?? "", connection, options);
  }
  return selectByRepository(
    args.image_registry ?? "",
    args.image_repository ?? "",
    connection,
    options,
  );
}
