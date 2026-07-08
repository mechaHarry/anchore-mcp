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
  if (t.length > 1024) {
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

function addValidFullReference(out: Set<string>, value: unknown): void {
  const reference = nonEmptyString(value);
  if (reference !== undefined && validateFullImageReference(reference).ok) {
    out.add(reference);
  }
}

function addDirectReferences(
  out: Set<string>,
  object: Record<string, unknown>,
  keys: readonly string[],
): void {
  for (const key of keys) {
    addValidFullReference(out, object[key]);
  }
  if (Array.isArray(object.tags)) {
    for (const tag of object.tags) {
      addValidFullReference(out, tag);
    }
  }
}

function addCoherentDetailReference(
  out: Set<string>,
  detail: Record<string, unknown>,
): void {
  const registry = nonEmptyString(detail.registry);
  const repo = nonEmptyString(detail.repo);
  const repository = nonEmptyString(detail.repository);
  const tag = nonEmptyString(detail.tag);

  // Conflicting aliases are not a coherent shape; never synthesize across them.
  if (
    registry === undefined ||
    tag === undefined ||
    !IMAGE_TAG_COMPONENT.test(tag) ||
    (repo !== undefined && repository !== undefined && repo !== repository)
  ) {
    return;
  }
  const coherentRepository = repo ?? repository;
  if (coherentRepository !== undefined) {
    addValidFullReference(
      out,
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
  const references = new Set<string>();
  addDirectReferences(references, object, TOP_LEVEL_FULL_REFERENCE_KEYS);

  for (const key of IMAGE_DETAIL_KEYS) {
    const raw = object[key];
    const details = Array.isArray(raw) ? raw : [raw];
    for (const detail of details) {
      if (detail === null || typeof detail !== "object") {
        continue;
      }
      const detailObject = detail as Record<string, unknown>;
      addDirectReferences(references, detailObject, DETAIL_FULL_REFERENCE_KEYS);
      addCoherentDetailReference(references, detailObject);
    }
  }

  return [...references];
}
