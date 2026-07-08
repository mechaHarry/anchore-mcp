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
