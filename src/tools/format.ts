import { prepareTextualToolText } from "../pii/warn.js";
import { toolContextSummary, type ToolContextFields } from "./context.js";

export type AnchoreToolPayload = {
  context: {
    profileName: string;
    baseUrl: string;
    account?: string;
    action: string;
    /** Same as `toolContextSummary` for R8 visibility. */
    summaryLine: string;
  };
  /** R14-masked textual summary (safe for chat). */
  summary: string;
  warnings: string[];
  /** Raw Anchore JSON — do not log wholesale to stderr (R13). */
  anchore: unknown;
};

/** Build the standard tool result JSON string (R8 + R14). */
export function formatAnchoreToolJson(
  ctx: ToolContextFields,
  summaryLine: string,
  anchore: unknown,
): string {
  const { text: summary, warnings } = prepareTextualToolText(summaryLine);
  const payload: AnchoreToolPayload = {
    context: {
      profileName: ctx.profileName,
      baseUrl: ctx.baseUrl,
      ...(ctx.account !== undefined ? { account: ctx.account } : {}),
      action: ctx.action,
      summaryLine: toolContextSummary(ctx),
    },
    summary,
    warnings,
    anchore,
  };
  return JSON.stringify(payload, null, 2);
}
