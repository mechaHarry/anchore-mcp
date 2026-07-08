import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { createAnchoreClient } from "../anchore/client.js";
import {
  getFallbackListImagesQueryKeys,
  getListImagesQueryParameterAllowlist,
  mergeListImagesQueryParams,
} from "../anchore/openapi-list-images-params.js";
import {
  DEFAULT_LIST_IMAGES_CAPS,
  fetchAllListImagesPages,
} from "../anchore/list-images-pages.js";
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
  /**
   * Extra query parameters for GET /v1|/v2/images. Keys must appear in the deployment
   * OpenAPI for this route (or the MCP fallback allowlist). Unknown keys are dropped and reported in the summary.
   */
  list_query?: Record<string, string>;
};

function summarizeImages(data: unknown, listQueryNote?: string): string {
  const note = listQueryNote !== undefined ? ` ${listQueryNote}` : "";
  if (data !== null && typeof data === "object") {
    if (
      "images" in data &&
      Array.isArray((data as { images: unknown }).images)
    ) {
      const n = (data as { images: unknown[] }).images.length;
      const base =
        n === 0
          ? "No images matched the query."
          : `Found ${n} image record(s) in Anchore.`;
      return `${base}${note}`;
    }
    /** V2 list responses often use `items` (see Anchore v1→v2 migration). */
    if ("items" in data && Array.isArray((data as { items: unknown }).items)) {
      const n = (data as { items: unknown[] }).items.length;
      const base =
        n === 0
          ? "No images matched the query."
          : `Found ${n} image record(s) in Anchore.`;
      return `${base}${note}`;
    }
  }
  if (Array.isArray(data)) {
    const base =
      data.length === 0
        ? "No images matched the query."
        : `Found ${data.length} image record(s) in Anchore.`;
    return `${base}${note}`;
  }
  return `Anchore returned image list data.${note}`;
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
    const listQueryKeys =
      args.list_query !== undefined ? Object.keys(args.list_query) : [];
    const allowlist =
      listQueryKeys.length > 0
        ? await getListImagesQueryParameterAllowlist(connection, {
            fetch: options?.fetch,
          })
        : new Set(getFallbackListImagesQueryKeys(connection.apiVersion));
    const { params, rejectedKeys } = mergeListImagesQueryParams(
      args,
      allowlist,
      connection.apiVersion,
    );
    let listQueryNote: string | undefined;
    if (rejectedKeys.length > 0) {
      const sample = rejectedKeys.slice(0, 8).join(", ");
      const more =
        rejectedKeys.length > 8 ? ` (+${rejectedKeys.length - 8} more)` : "";
      listQueryNote = `Note: dropped ${rejectedKeys.length} list_query key(s) not allowlisted for this deployment: ${sample}${more}.`;
    }
    const {
      mergedBody,
      enumerationIncomplete,
      incompleteReason,
    } = await fetchAllListImagesPages(
      client,
      connection,
      params,
      DEFAULT_LIST_IMAGES_CAPS,
    );
    let data: unknown = mergedBody;
    if (enumerationIncomplete) {
      if (Array.isArray(data)) {
        data = {
          items: data,
          listEnumerationIncomplete: true,
          listEnumerationReason: incompleteReason,
        };
      } else if (data !== null && typeof data === "object") {
        data = {
          ...(data as Record<string, unknown>),
          listEnumerationIncomplete: true,
          listEnumerationReason: incompleteReason,
        };
      } else {
        data = {
          merged: mergedBody,
          listEnumerationIncomplete: true,
          listEnumerationReason: incompleteReason,
        };
      }
    }
    const ctx: ToolContextFields = {
      baseUrl: connection.baseUrl,
      account: connection.account,
      apiVersion: connection.apiVersion,
      action: "list images",
    };
    const summaryLine = summarizeImages(data, listQueryNote);
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
