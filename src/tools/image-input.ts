import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { ResolvedAnchoreConnection } from "../config/connection.js";
import {
  resolveImageReference,
  type ResolveImageReferenceResult,
} from "../anchore/resolve-image-reference.js";
import type { AnchoreToolRunOptions } from "./anchore-run-options.js";
import type { ToolContextFields } from "./context.js";
import { formatAnchoreToolJson } from "./format.js";

export type ImageDigestOrReferenceArgs = {
  image_digest?: string;
  image_reference?: string;
};

export type ResolvedDigestOk = {
  ok: true;
  digest: string;
  /** Set when digest came from resolving image_reference (R6). */
  resolvedFromImageReference?: string;
};

function toolErrorJson(message: string): CallToolResult {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify({ error: true, message }, null, 2),
      },
    ],
    isError: true,
  };
}

function resolutionContext(
  connection: ResolvedAnchoreConnection,
  action: string,
  resolvedFromImageReference?: string,
): ToolContextFields {
  return {
    baseUrl: connection.baseUrl,
    account: connection.account,
    apiVersion: connection.apiVersion,
    action,
    ...(resolvedFromImageReference !== undefined
      ? { resolvedFromImageReference }
      : {}),
  };
}

function resolutionFailureResult(
  connection: ResolvedAnchoreConnection,
  action: string,
  outcome: Exclude<ResolveImageReferenceResult, { kind: "ok" }>,
  resolvedFromImageReference: string,
): CallToolResult {
  const ctx = resolutionContext(connection, `${action} (resolve reference)`, resolvedFromImageReference);
  let summaryLine: string;
  if (outcome.kind === "no_match") {
    summaryLine = "No analyzed image matched this reference (fulltag list returned no digest).";
  } else if (outcome.kind === "disambiguate") {
    summaryLine = `Multiple digests matched this reference (${outcome.candidates.length} candidate(s)); disambiguation required.`;
  } else if (outcome.kind === "enumeration_incomplete") {
    summaryLine = `Image list enumeration stopped before results were complete: ${outcome.reason}`;
  } else {
    summaryLine = outcome.message;
  }
  const anchore = { imageReferenceResolution: outcome };
  const text = formatAnchoreToolJson(ctx, summaryLine, anchore);
  return { content: [{ type: "text", text }], isError: true };
}

/**
 * Validate XOR digest/reference and resolve reference to a path digest when needed.
 */
export async function resolveDigestForAnchorePath(
  args: ImageDigestOrReferenceArgs,
  connection: ResolvedAnchoreConnection,
  options: AnchoreToolRunOptions | undefined,
  action: string,
): Promise<ResolvedDigestOk | { ok: false; result: CallToolResult }> {
  const d = args.image_digest?.trim() ?? "";
  const r = args.image_reference?.trim() ?? "";

  if (d.length > 0 && r.length > 0) {
    return {
      ok: false,
      result: toolErrorJson(
        "Provide exactly one of image_digest or image_reference, not both.",
      ),
    };
  }
  if (d.length === 0 && r.length === 0) {
    return {
      ok: false,
      result: toolErrorJson("Provide either image_digest or image_reference."),
    };
  }

  if (d.length > 0) {
    return { ok: true, digest: d };
  }

  const outcome = await resolveImageReference(connection, r, {
    fetch: options?.fetch,
  });
  if (outcome.kind === "ok") {
    return {
      ok: true,
      digest: outcome.digest,
      resolvedFromImageReference: r,
    };
  }
  return {
    ok: false,
    result: resolutionFailureResult(connection, action, outcome, r),
  };
}
