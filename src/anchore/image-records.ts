/**
 * Normalize Anchore list/detail image rows across v1/v2 response shapes.
 */

/** Extract list rows from GET /v1|/v2/images list payloads (single page or merged). */
export function extractImageListRows(data: unknown): unknown[] {
  if (data === null || data === undefined) {
    return [];
  }
  if (Array.isArray(data)) {
    return data;
  }
  if (typeof data === "object") {
    const o = data as Record<string, unknown>;
    if ("images" in o && Array.isArray(o.images)) {
      return o.images;
    }
    if ("items" in o && Array.isArray(o.items)) {
      return o.items;
    }
  }
  return [];
}

/** Best-effort digest field from an image list row. */
export function digestFromImageRow(row: unknown): string | undefined {
  if (row === null || typeof row !== "object") {
    return undefined;
  }
  const o = row as Record<string, unknown>;
  const candidates = [
    o.imageDigest,
    o.image_digest,
    o.digest,
    o.imageId,
    o.image_id,
  ];
  for (const c of candidates) {
    if (typeof c === "string" && c.trim().length > 0) {
      return c.trim();
    }
  }
  return undefined;
}

const SHA256_HEX = /^sha256:[a-f0-9]{64}$/i;
export const MAX_IMAGE_REFERENCE_STRING_LENGTH = 1024;
export const MAX_IMAGE_DETAIL_ENTRIES_PER_ROW = 64;
export const MAX_IMAGE_TAG_ENTRIES_PER_OBJECT = 64;
export const MAX_NORMALIZED_IMAGE_REFERENCES_PER_ROW = 32;
export const MAX_IMAGE_REFERENCE_EVIDENCE_SCANS_PER_ROW = 256;
const MAX_REGISTRY_COMPONENT_LENGTH = 255;
const MAX_REPOSITORY_COMPONENT_LENGTH = 1024;

/** True when the string should be treated as a canonical digest path key (R2). */
export function isCanonicalImageDigestString(s: string): boolean {
  const t = s.trim();
  if (t.length < 12 || t.length > 512) {
    return false;
  }
  if (SHA256_HEX.test(t)) {
    return true;
  }
  if (t.startsWith("sha256:") && /^sha256:[a-f0-9]+$/i.test(t)) {
    return true;
  }
  return false;
}

/**
 * Full image reference validation: require registry/repo:tag style (contains `/` and `:`).
 * Rejects bare short names like `nginx:latest` (plan default).
 */
export function validateFullImageReference(ref: string): { ok: true } | { ok: false; message: string } {
  const t = ref.trim();
  if (t.length === 0) {
    return { ok: false, message: "image_reference is empty." };
  }
  if (t.length > MAX_IMAGE_REFERENCE_STRING_LENGTH) {
    return { ok: false, message: "image_reference is too long." };
  }
  // eslint-disable-next-line no-control-regex -- reject ASCII control chars in references
  if (/[\x00-\x1f\x7f]/.test(t)) {
    return { ok: false, message: "image_reference contains invalid control characters." };
  }
  const lastSlash = t.lastIndexOf("/");
  if (lastSlash < 0) {
    return {
      ok: false,
      message:
        "image_reference must be a fully qualified image reference (e.g. docker.io/library/nginx:latest).",
    };
  }
  const lastColon = t.lastIndexOf(":");
  if (lastColon <= lastSlash || lastColon === t.length - 1) {
    return { ok: false, message: "image_reference must include a tag (registry/repo:tag)." };
  }
  return { ok: true };
}

const TOP_LEVEL_FULL_REFERENCE_KEYS = [
  "full_tag",
  "fulltag",
  "image_tag",
  "imageTag",
  "tag",
] as const;
const DETAIL_FULL_REFERENCE_KEYS = [
  "full_tag",
  "fulltag",
  "image_tag",
  "imageTag",
] as const;
const IMAGE_DETAIL_KEYS = ["image_detail", "imageDetail"] as const;
const IMAGE_TAG_COMPONENT = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;

function nonEmptyString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0
    ? value.trim()
    : undefined;
}

type ReferenceEvidence = {
  references: Set<string>;
  scans: number;
  invalid: boolean;
};

function consumeEvidence(evidence: ReferenceEvidence): boolean {
  evidence.scans += 1;
  if (evidence.scans > MAX_IMAGE_REFERENCE_EVIDENCE_SCANS_PER_ROW) {
    evidence.invalid = true;
    return false;
  }
  return true;
}

function boundedString(
  evidence: ReferenceEvidence,
  value: unknown,
  maxLength: number,
): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (!consumeEvidence(evidence)) {
    return undefined;
  }
  if (typeof value !== "string") {
    return undefined;
  }
  if (value.length > maxLength) {
    evidence.invalid = true;
    return undefined;
  }
  return nonEmptyString(value);
}

function addValidFullReference(
  evidence: ReferenceEvidence,
  value: unknown,
): void {
  const reference = boundedString(
    evidence,
    value,
    MAX_IMAGE_REFERENCE_STRING_LENGTH,
  );
  if (reference !== undefined && validateFullImageReference(reference).ok) {
    evidence.references.add(reference);
    if (
      evidence.references.size > MAX_NORMALIZED_IMAGE_REFERENCES_PER_ROW
    ) {
      evidence.invalid = true;
    }
  }
}

function addDirectReferences(
  evidence: ReferenceEvidence,
  object: Record<string, unknown>,
  keys: readonly string[],
): void {
  for (const key of keys) {
    addValidFullReference(evidence, object[key]);
  }
  if (Array.isArray(object.tags)) {
    if (object.tags.length > MAX_IMAGE_TAG_ENTRIES_PER_OBJECT) {
      evidence.invalid = true;
      return;
    }
    for (const tag of object.tags) {
      addValidFullReference(evidence, tag);
    }
  }
}

function validRegistryComponent(registry: string): boolean {
  // eslint-disable-next-line no-control-regex -- registry evidence must reject controls
  const invalidRegistryCharacters = /[\s/\\\x00-\x1f\x7f]/;
  if (
    registry.length === 0 ||
    registry.length > MAX_REGISTRY_COMPONENT_LENGTH ||
    invalidRegistryCharacters.test(registry)
  ) {
    return false;
  }

  const bracketed = registry.match(/^\[([0-9A-Fa-f:.]+)\](?::(\d{1,5}))?$/);
  if (bracketed !== null) {
    const port = bracketed[2];
    return port === undefined || (Number(port) > 0 && Number(port) <= 65_535);
  }

  const parts = registry.split(":");
  if (parts.length > 2) {
    return false;
  }
  const host = parts[0];
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/.test(host)) {
    return false;
  }
  if (parts.length === 2) {
    if (!/^\d{1,5}$/.test(parts[1])) {
      return false;
    }
    const port = Number(parts[1]);
    if (port <= 0 || port > 65_535) {
      return false;
    }
  }
  return true;
}

function validRepositoryComponent(repository: string): boolean {
  // eslint-disable-next-line no-control-regex -- repository evidence must reject controls
  const invalidRepositoryCharacters = /[\s:\\\x00-\x1f\x7f]/;
  return (
    repository.length > 0 &&
    repository.length <= MAX_REPOSITORY_COMPONENT_LENGTH &&
    !repository.startsWith("/") &&
    !repository.endsWith("/") &&
    !repository.includes("//") &&
    !invalidRepositoryCharacters.test(repository)
  );
}

function addCoherentDetailReference(
  evidence: ReferenceEvidence,
  detail: Record<string, unknown>,
): void {
  const registry = boundedString(
    evidence,
    detail.registry,
    MAX_REGISTRY_COMPONENT_LENGTH,
  );
  const repo = boundedString(
    evidence,
    detail.repo,
    MAX_REPOSITORY_COMPONENT_LENGTH,
  );
  const repository = boundedString(
    evidence,
    detail.repository,
    MAX_REPOSITORY_COMPONENT_LENGTH,
  );
  const tag = boundedString(evidence, detail.tag, 128);

  // Conflicting aliases are not a coherent shape; never synthesize across them.
  if (
    registry === undefined ||
    !validRegistryComponent(registry) ||
    tag === undefined ||
    !IMAGE_TAG_COMPONENT.test(tag) ||
    (repo !== undefined && repository !== undefined && repo !== repository)
  ) {
    return;
  }
  const coherentRepository = repo ?? repository;
  if (
    coherentRepository !== undefined &&
    validRepositoryComponent(coherentRepository)
  ) {
    addValidFullReference(
      evidence,
      `${registry}/${coherentRepository}:${tag}`,
    );
  }
}

/**
 * Extract locally provable full references from one image row without combining
 * fields across objects or incompatible aliases.
 */
export function fullImageReferencesFromRow(row: unknown): string[] {
  if (row === null || typeof row !== "object") {
    return [];
  }
  const object = row as Record<string, unknown>;
  const evidence: ReferenceEvidence = {
    references: new Set<string>(),
    scans: 0,
    invalid: false,
  };
  addDirectReferences(evidence, object, TOP_LEVEL_FULL_REFERENCE_KEYS);

  let detailEntryCount = 0;
  for (const key of IMAGE_DETAIL_KEYS) {
    const raw = object[key];
    const details = Array.isArray(raw)
      ? raw
      : raw !== null && typeof raw === "object"
        ? [raw]
        : [];
    detailEntryCount += details.length;
    if (detailEntryCount > MAX_IMAGE_DETAIL_ENTRIES_PER_ROW) {
      return [];
    }
    for (const detail of details) {
      if (detail === null || typeof detail !== "object") {
        continue;
      }
      if (!consumeEvidence(evidence)) {
        return [];
      }
      const detailObject = detail as Record<string, unknown>;
      addDirectReferences(evidence, detailObject, DETAIL_FULL_REFERENCE_KEYS);
      addCoherentDetailReference(evidence, detailObject);
      if (evidence.invalid) {
        return [];
      }
    }
  }

  return evidence.invalid ? [] : [...evidence.references];
}
