import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { createAnchoreClient } from "../anchore/client.js";
import type { ProfileRegistry } from "../config/profiles.js";
import { logStderrLine } from "../logging/safe-log.js";
import { anchoreFailureMessage } from "./anchore-tool-error.js";
import type { ToolContextFields } from "./context.js";
import { formatAnchoreToolJson } from "./format.js";

export type ListImagesArgs = {
  /** Profile name; defaults to config `defaultProfile`. */
  profile?: string;
  /** If supported by your Anchore build, filter by full image tag. */
  fulltag?: string;
  /** If supported, filter by CVE id (e.g. CVE-2024-1234). */
  vulnerability_id?: string;
};

function summarizeImages(data: unknown): string {
  if (
    data !== null &&
    typeof data === "object" &&
    "images" in data &&
    Array.isArray((data as { images: unknown }).images)
  ) {
    const n = (data as { images: unknown[] }).images.length;
    return n === 0
      ? "No images matched the query."
      : `Found ${n} image record(s) in Anchore.`;
  }
  if (Array.isArray(data)) {
    return data.length === 0
      ? "No images matched the query."
      : `Found ${data.length} image record(s) in Anchore.`;
  }
  return "Anchore returned image list data.";
}

/**
 * GET /v1/images with optional query parameters (support varies by version — see deployment Swagger).
 */
export async function runListImages(
  registry: ProfileRegistry,
  args: ListImagesArgs,
  options?: { fetch?: typeof fetch },
): Promise<CallToolResult> {
  try {
    const profile = registry.resolve(args.profile);
    const client = createAnchoreClient(profile, options);
    const params = new URLSearchParams();
    if (args.fulltag) {
      params.set("fulltag", args.fulltag);
    }
    if (args.vulnerability_id) {
      params.set("vulnerability_id", args.vulnerability_id);
    }
    const qs = params.toString();
    const path = qs ? `/v1/images?${qs}` : "/v1/images";
    const data = await client.getJson<unknown>(path);
    const ctx: ToolContextFields = {
      profileName: profile.profileName,
      baseUrl: profile.baseUrl,
      account: profile.account,
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
