/**
 * R8 — operator-visible, non-secret context for Anchore tool results.
 * Compose with textual PII helpers (`prepareTextualToolText`) for free-form lines only.
 */

export type ToolContextFields = {
  profileName: string;
  baseUrl: string;
  /** Anchore account name when scoped. */
  account?: string;
  /** Short verb phrase, e.g. "list images", "get vulnerabilities". */
  action: string;
};

/** Single-line summary for embedding in text or structured `context` fields. */
export function toolContextSummary(ctx: ToolContextFields): string {
  const acct = ctx.account ? ` | account: ${ctx.account}` : "";
  return `${ctx.profileName} @ ${ctx.baseUrl}${acct} — ${ctx.action}`;
}
