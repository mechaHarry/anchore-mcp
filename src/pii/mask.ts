/**
 * R14 — Heuristic masking for **textual** tool content only. JSON returned to the client is not
 * passed through this module; it must not be written wholesale to stderr (see `logging/safe-log`).
 */

export type PiiMatchKind = "email" | "ssn_like" | "phone_like";

const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}\b/g;

/** US SSN-style ###-##-#### (may false-positive on other numeric IDs). */
const SSN_LIKE = /\b\d{3}-\d{2}-\d{4}\b/g;

/** Common NA phone shapes (digits + separators). */
const PHONE_LIKE =
  /\b(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b/g;

function pushKind(list: PiiMatchKind[], kind: PiiMatchKind): void {
  if (!list.includes(kind)) {
    list.push(kind);
  }
}

/**
 * Mask likely PII substrings in prose or unstructured text. Returns kinds detected (deduped).
 */
export function maskPiiText(input: string): { masked: string; kinds: PiiMatchKind[] } {
  const kinds: PiiMatchKind[] = [];
  let masked = input;

  masked = masked.replace(EMAIL, () => {
    pushKind(kinds, "email");
    return "[email redacted]";
  });

  masked = masked.replace(SSN_LIKE, () => {
    pushKind(kinds, "ssn_like");
    return "[id redacted]";
  });

  masked = masked.replace(PHONE_LIKE, () => {
    pushKind(kinds, "phone_like");
    return "[phone redacted]";
  });

  return { masked, kinds };
}
