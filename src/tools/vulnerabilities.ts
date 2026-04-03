import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { createAnchoreClient } from "../anchore/client.js";
import type { ResolvedAnchoreConnection } from "../config/connection.js";
import { logStderrLine } from "../logging/safe-log.js";
import { anchoreFailureMessage } from "./anchore-tool-error.js";
import type { ToolContextFields } from "./context.js";
import { formatAnchoreToolJson } from "./format.js";

export type ImageVulnerabilitiesArgs = {
  /** Image digest, e.g. sha256:… */
  image_digest: string;
};

function summarizeVulnerabilities(data: unknown): string {
  if (
    data !== null &&
    typeof data === "object" &&
    "vulnerabilities" in data &&
    Array.isArray((data as { vulnerabilities: unknown }).vulnerabilities)
  ) {
    const n = (data as { vulnerabilities: unknown[] }).vulnerabilities.length;
    return n === 0
      ? "No vulnerabilities reported for this image."
      : `Found ${n} vulnerability record(s) for this image.`;
  }
  if (Array.isArray(data)) {
    return data.length === 0
      ? "No vulnerabilities reported for this image."
      : `Found ${data.length} vulnerability record(s) for this image.`;
  }
  return "Vulnerability data retrieved from Anchore.";
}

/**
 * GET /v1/images/{imageDigest}/vulnerabilities
 */
export async function runImageVulnerabilities(
  connection: ResolvedAnchoreConnection,
  args: ImageVulnerabilitiesArgs,
  options?: { fetch?: typeof fetch },
): Promise<CallToolResult> {
  const digest = args.image_digest.trim();
  if (!digest) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            { error: true, message: "image_digest is required." },
            null,
            2,
          ),
        },
      ],
      isError: true,
    };
  }

  try {
    const client = createAnchoreClient(connection, options);
    const encoded = encodeURIComponent(digest);
    const path = `/v1/images/${encoded}/vulnerabilities`;
    const data = await client.getJson<unknown>(path);
    const ctx: ToolContextFields = {
      baseUrl: connection.baseUrl,
      account: connection.account,
      action: "image vulnerabilities",
    };
    const summaryLine = summarizeVulnerabilities(data);
    const text = formatAnchoreToolJson(ctx, summaryLine, data);
    return { content: [{ type: "text", text }] };
  } catch (err) {
    logStderrLine(`anchore_image_vulnerabilities: ${anchoreFailureMessage(err)}`);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            { error: true, message: anchoreFailureMessage(err) },
            null,
            2,
          ),
        },
      ],
      isError: true,
    };
  }
}
