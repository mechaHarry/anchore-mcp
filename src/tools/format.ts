import type { AnchoreApiVersion } from "../anchore/api-paths.js";
import { prepareTextualToolText } from "../pii/warn.js";
import { toolContextSummary, type ToolContextFields } from "./context.js";

export type AnchoreToolPayload = {
  context: {
    baseUrl: string;
    account?: string;
    apiVersion: AnchoreApiVersion;
    action: string;
    /** Same as `toolContextSummary` for R8 visibility. */
    summaryLine: string;
  };
  /** R14-masked textual summary (safe for chat). */
  summary: string;
  warnings: string[];
  /** R15 — UTF-8 byte length of the Anchore HTTP response body when measured. */
  sizeBytes?: number;
  /** Raw Anchore JSON — do not log wholesale to stderr (R13). */
  anchore: unknown;
};

export type FormatAnchoreToolJsonMeta = {
  sizeBytes?: number;
};

/** Build the standard tool result JSON string (R8 + R14). */
export function formatAnchoreToolJson(
  ctx: ToolContextFields,
  summaryLine: string,
  anchore: unknown,
  meta?: FormatAnchoreToolJsonMeta,
): string {
  const { text: summary, warnings } = prepareTextualToolText(summaryLine);
  const payload: AnchoreToolPayload = {
    context: {
      baseUrl: ctx.baseUrl,
      apiVersion: ctx.apiVersion,
      ...(ctx.account !== undefined ? { account: ctx.account } : {}),
      action: ctx.action,
      summaryLine: toolContextSummary(ctx),
    },
    summary,
    warnings,
    ...(meta?.sizeBytes !== undefined ? { sizeBytes: meta.sizeBytes } : {}),
    anchore,
  };
  return JSON.stringify(payload, null, 2);
}
