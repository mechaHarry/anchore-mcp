import type { ResolvedAnchoreConnection } from "../config/connection.js";
import { createAnchoreClient, type AnchoreClientOptions } from "./client.js";
import {
  digestFromImageRow,
  extractImageListRows,
  validateFullImageReference,
} from "./image-records.js";
import {
  DEFAULT_RESOLUTION_LIST_CAPS,
  fetchAllListImagesPages,
} from "./list-images-pages.js";

export type PolicyBlockingImageLocator = {
  image_digest?: string;
  image_reference?: string;
  image_repository?: string;
};

export type SelectedImage = {
  digest: string;
  reference?: string;
  repository?: string;
  analysisTimestamp?: string;
};

export type ImageSelectionResult =
  | { ok: true; selectedImage: SelectedImage }
  | { ok: false; status: "image_selection_error"; message: string };

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

const REPOSITORY_KEYS = [
  "repository",
  "repo",
  "image_repository",
  "imageRepository",
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

function imageSelectionError(message: string): ImageSelectionResult {
  return { ok: false, status: "image_selection_error", message };
}

function nonEmptyLocatorEntries(
  args: PolicyBlockingImageLocator,
): Array<[keyof PolicyBlockingImageLocator, string]> {
  const entries: Array<[keyof PolicyBlockingImageLocator, string]> = [];
  for (const key of ["image_digest", "image_reference", "image_repository"] as const) {
    const value = args[key];
    if (typeof value === "string" && value.trim().length > 0) {
      entries.push([key, value.trim()]);
    }
  }
  return entries;
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

function detailRepositories(detail: Record<string, unknown>): string[] {
  const values = stringFields(detail, REPOSITORY_KEYS);
  const registry = stringField(detail, "registry");
  const repo = stringField(detail, "repo") ?? stringField(detail, "repository");
  if (registry !== undefined && repo !== undefined) {
    values.push(`${registry}/${repo}`);
  }
  for (const reference of detailReferences(detail)) {
    const derived = stripTagFromReference(reference);
    if (derived !== undefined) {
      values.push(derived);
    }
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
    const value = stringField(row, key);
    if (value === undefined) {
      continue;
    }
    const parsed = Date.parse(value);
    if (Number.isFinite(parsed)) {
      return { value, parsed };
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

function validateRepository(repository: string): { ok: true } | { ok: false; message: string } {
  const trimmed = repository.trim();
  if (trimmed.length === 0) {
    return { ok: false, message: "image_repository is empty." };
  }
  if (trimmed.length > 1024) {
    return { ok: false, message: "image_repository is too long." };
  }
  // eslint-disable-next-line no-control-regex -- reject ASCII control chars in image repository input
  if (/[\x00-\x1f\x7f]/.test(trimmed)) {
    return { ok: false, message: "image_repository contains invalid control characters." };
  }
  const lastSlash = trimmed.lastIndexOf("/");
  if (lastSlash <= 0 || lastSlash === trimmed.length - 1) {
    return {
      ok: false,
      message:
        "image_repository must be a qualified registry/repository string (e.g. docker.io/library/nginx).",
    };
  }
  const lastColon = trimmed.lastIndexOf(":");
  if (lastColon > lastSlash) {
    return { ok: false, message: "image_repository must not include an image tag." };
  }
  return { ok: true };
}

function repositoriesFromRow(row: Record<string, unknown>): string[] {
  const repositories = stringFields(row, REPOSITORY_KEYS);
  for (const detail of imageDetailRows(row)) {
    repositories.push(...detailRepositories(detail));
  }
  for (const reference of referencesFromRow(row)) {
    const derived = stripTagFromReference(reference);
    if (derived !== undefined) {
      repositories.push(derived);
    }
  }
  return uniqueStrings(repositories);
}

function referenceMatchesRepository(reference: string, repository: string): boolean {
  const derived = stripTagFromReference(reference);
  if (derived === undefined) {
    return false;
  }
  return derived === repository || derived.endsWith(`/${repository}`);
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
  options?: AnchoreClientOptions,
): Promise<ImageSelectionResult | unknown[]> {
  const client = createAnchoreClient(connection, options);
  try {
    const out = await fetchAllListImagesPages(
      client,
      connection,
      params,
      DEFAULT_RESOLUTION_LIST_CAPS,
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
    return imageSelectionError(message);
  }
}

async function selectByReference(
  imageReference: string,
  connection: ResolvedAnchoreConnection,
  options?: AnchoreClientOptions,
): Promise<ImageSelectionResult> {
  const validated = validateFullImageReference(imageReference);
  if (!validated.ok) {
    return imageSelectionError(validated.message);
  }

  const reference = imageReference.trim();
  const params = new URLSearchParams();
  params.set("fulltag", reference);

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
    const timestamp = timestampFromRow(objectRow);
    if (digest === undefined || timestamp === undefined) {
      continue;
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
  imageRepository: string,
  connection: ResolvedAnchoreConnection,
  options?: AnchoreClientOptions,
): Promise<ImageSelectionResult> {
  const repository = imageRepository.trim();
  const validated = validateRepository(repository);
  if (!validated.ok) {
    return imageSelectionError(validated.message);
  }

  const params = new URLSearchParams();
  params.set("repository", repository);

  const rows = await listImages(params, connection, options);
  if (!Array.isArray(rows)) {
    return rows;
  }

  const candidates: TimestampedCandidate[] = [];
  for (const row of rows) {
    if (row === null || typeof row !== "object") {
      continue;
    }
    const objectRow = row as Record<string, unknown>;
    if (!repositoriesFromRow(objectRow).includes(repository)) {
      continue;
    }
    const digest = digestFromImageRow(objectRow);
    const timestamp = timestampFromRow(objectRow);
    if (digest === undefined || timestamp === undefined) {
      continue;
    }
    const reference = referencesFromRow(objectRow).find((candidate) =>
      referenceMatchesRepository(candidate, repository),
    );
    candidates.push({
      digest,
      ...(reference !== undefined ? { reference } : {}),
      repository,
      analysisTimestamp: timestamp.value,
      parsedTimestamp: timestamp.parsed,
    });
  }

  return selectNewest(candidates);
}

export async function selectImageForPolicyBlockingReport(
  args: PolicyBlockingImageLocator,
  connection: ResolvedAnchoreConnection,
  options?: AnchoreClientOptions,
): Promise<ImageSelectionResult> {
  const locators = nonEmptyLocatorEntries(args);
  if (locators.length !== 1) {
    return imageSelectionError(
      "Supply exactly one of image_digest, image_reference, or image_repository.",
    );
  }

  const [kind, value] = locators[0];
  if (kind === "image_digest") {
    return { ok: true, selectedImage: { digest: value } };
  }
  if (kind === "image_reference") {
    return selectByReference(value, connection, options);
  }
  return selectByRepository(value, connection, options);
}
