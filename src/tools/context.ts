import type { AnchoreApiVersion } from "../anchore/api-paths.js";

/**
 * R8 — operator-visible, non-secret context for Anchore tool results.
 * Compose with textual PII helpers (`prepareTextualToolText`) for free-form lines only.
 */

export type ToolContextFields = {
  baseUrl: string;
  /** Anchore account name when scoped. */
  account?: string;
  /** REST API path version in use (`/v1/...` vs `/v2/...`). */
  apiVersion: AnchoreApiVersion;
  /** Short verb phrase, e.g. "list images", "get vulnerabilities". */
  action: string;
  /** When digest was resolved from image_reference (R6). */
  resolvedFromImageReference?: string;
};

/** Single-line summary for embedding in text or structured `context` fields. */
export function toolContextSummary(ctx: ToolContextFields): string {
  const acct = ctx.account ? ` | account: ${ctx.account}` : "";
  return `${ctx.apiVersion} | ${ctx.baseUrl}${acct} — ${ctx.action}`;
}
