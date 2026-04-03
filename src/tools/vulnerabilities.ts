import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { imageVulnerabilitiesPath } from "../anchore/api-paths.js";
import { createAnchoreClient } from "../anchore/client.js";
import { loadConnectionFromEnv } from "../config/connection.js";
import { logStderrLine } from "../logging/safe-log.js";
import type { AnchoreToolRunOptions } from "./anchore-run-options.js";
import { anchoreFailureMessage } from "./anchore-tool-error.js";
import type { ToolContextFields } from "./context.js";
import { formatAnchoreToolJson } from "./format.js";

export type ImageVulnerabilitiesArgs = {
  /** Image digest, e.g. sha256:… */
  image_digest: string;
};

function countVulnerabilityRecords(data: unknown): number | null {
  if (data !== null && typeof data === "object") {
    if (
      "vulnerabilities" in data &&
      Array.isArray((data as { vulnerabilities: unknown }).vulnerabilities)
    ) {
      return (data as { vulnerabilities: unknown[] }).vulnerabilities.length;
    }
    if ("items" in data && Array.isArray((data as { items: unknown }).items)) {
      return (data as { items: unknown[] }).items.length;
    }
  }
  if (Array.isArray(data)) {
    return data.length;
  }
  return null;
}

function summarizeVulnerabilities(data: unknown): string {
  const n = countVulnerabilityRecords(data);
  if (n !== null) {
    return n === 0
      ? "No vulnerabilities reported for this image."
      : `Found ${n} vulnerability record(s) for this image.`;
  }
  return "Vulnerability data retrieved from Anchore.";
}

/**
 * V2: GET /v2/images/{digest}/vuln/all — V1: GET /v1/images/{digest}/vulnerabilities
 */
export async function runImageVulnerabilities(
  args: ImageVulnerabilitiesArgs,
  options?: AnchoreToolRunOptions,
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

  let connection;
  try {
    connection = options?.connection ?? loadConnectionFromEnv();
  } catch (err) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              error: true,
              message:
                err instanceof Error
                  ? err.message
                  : "Anchore connection is not configured.",
            },
            null,
            2,
          ),
        },
      ],
      isError: true,
    };
  }

  try {
    const client = createAnchoreClient(connection, { fetch: options?.fetch });
    const path = imageVulnerabilitiesPath(connection.apiVersion, digest);
    const data = await client.getJson<unknown>(path);
    const ctx: ToolContextFields = {
      baseUrl: connection.baseUrl,
      account: connection.account,
      apiVersion: connection.apiVersion,
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
