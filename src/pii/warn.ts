import { maskPiiText, type PiiMatchKind } from "./mask.js";

const MESSAGES: Record<PiiMatchKind, string> = {
  email:
    "Possible email address was masked in the text above. Limit distribution and verify recipients before sharing.",
  ssn_like:
    "Possible government ID / SSN-like pattern was masked. Treat any remaining content as sensitive.",
  phone_like:
    "Possible phone number was masked. Verify before sharing outside your trust boundary.",
};

/** Human-readable warnings for detected PII kinds (deduped order). */
export function piiWarnings(kinds: readonly PiiMatchKind[]): string[] {
  const seen = new Set<PiiMatchKind>();
  const out: string[] = [];
  for (const k of kinds) {
    if (seen.has(k)) {
      continue;
    }
    seen.add(k);
    out.push(MESSAGES[k]);
  }
  return out;
}

/**
 * Apply R14 to a **textual** segment: mask heuristics + collect warnings for chat tool results.
 */
export function prepareTextualToolText(input: string): {
  text: string;
  warnings: string[];
} {
  const { masked, kinds } = maskPiiText(input);
  return { text: masked, warnings: piiWarnings(kinds) };
}
