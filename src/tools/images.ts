import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { imagesListPath } from "../anchore/api-paths.js";
import { createAnchoreClient } from "../anchore/client.js";
import { loadConnectionFromEnv } from "../config/connection.js";
import { logStderrLine } from "../logging/safe-log.js";
import type { AnchoreToolRunOptions } from "./anchore-run-options.js";
import { anchoreFailureMessage } from "./anchore-tool-error.js";
import type { ToolContextFields } from "./context.js";
import { formatAnchoreToolJson } from "./format.js";

export type ListImagesArgs = {
  /** If supported by your Anchore build, filter by full image tag. */
  fulltag?: string;
  /** If supported, filter by CVE id (e.g. CVE-2024-1234). */
  vulnerability_id?: string;
};

function summarizeImages(data: unknown): string {
  if (data !== null && typeof data === "object") {
    if (
      "images" in data &&
      Array.isArray((data as { images: unknown }).images)
    ) {
      const n = (data as { images: unknown[] }).images.length;
      return n === 0
        ? "No images matched the query."
        : `Found ${n} image record(s) in Anchore.`;
    }
    /** V2 list responses often use `items` (see Anchore v1→v2 migration). */
    if ("items" in data && Array.isArray((data as { items: unknown }).items)) {
      const n = (data as { items: unknown[] }).items.length;
      return n === 0
        ? "No images matched the query."
        : `Found ${n} image record(s) in Anchore.`;
    }
  }
  if (Array.isArray(data)) {
    return data.length === 0
      ? "No images matched the query."
      : `Found ${data.length} image record(s) in Anchore.`;
  }
  return "Anchore returned image list data.";
}

/**
 * GET /v2/images (default) or /v1/images with optional query parameters — see deployment OpenAPI.
 */
export async function runListImages(
  args: ListImagesArgs,
  options?: AnchoreToolRunOptions,
): Promise<CallToolResult> {
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
    const params = new URLSearchParams();
    if (args.fulltag) {
      params.set("fulltag", args.fulltag);
    }
    if (args.vulnerability_id) {
      params.set("vulnerability_id", args.vulnerability_id);
    }
    const path = imagesListPath(connection.apiVersion, params);
    const data = await client.getJson<unknown>(path);
    const ctx: ToolContextFields = {
      baseUrl: connection.baseUrl,
      account: connection.account,
      apiVersion: connection.apiVersion,
      action: "list images",
    };
    const summaryLine = summarizeImages(data);
    const text = formatAnchoreToolJson(ctx, summaryLine, data);
    return { content: [{ type: "text", text }] };
  } catch (err) {
    logStderrLine(`anchore_list_images: ${anchoreFailureMessage(err)}`);
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
