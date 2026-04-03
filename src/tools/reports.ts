import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { imageByDigestPath, imagePolicyCheckPath } from "../anchore/api-paths.js";
import { createAnchoreClient } from "../anchore/client.js";
import { loadConnectionFromEnv } from "../config/connection.js";
import { logStderrLine } from "../logging/safe-log.js";
import type { AnchoreToolRunOptions } from "./anchore-run-options.js";
import { anchoreFailureMessage } from "./anchore-tool-error.js";
import type { ToolContextFields } from "./context.js";
import { formatAnchoreToolJson } from "./format.js";

export type ImagePolicyCheckArgs = {
  image_digest: string;
  /** When required by your Anchore version, the image tag (e.g. `docker.io/library/nginx:latest`). */
  tag?: string;
  /** Optional base image digest for comparison policy checks. */
  base_digest?: string;
};

export type ImageDetailArgs = {
  image_digest: string;
};

function summarizePolicy(data: unknown): string {
  if (data !== null && typeof data === "object" && "status" in data) {
    const st = (data as { status?: unknown }).status;
    return `Policy evaluation returned (status: ${String(st)}).`;
  }
  if (Array.isArray(data)) {
    return `Policy evaluation returned ${data.length} record(s).`;
  }
  return "Policy evaluation data retrieved from Anchore.";
}

function summarizeImageDetail(data: unknown): string {
  if (data !== null && typeof data === "object") {
    const d = data as Record<string, unknown>;
    if (typeof d.image_digest === "string") {
      return `Image record for digest ${d.image_digest}.`;
    }
    if (typeof d.imageDigest === "string") {
      return `Image record for digest ${d.imageDigest}.`;
    }
  }
  return "Image detail retrieved from Anchore.";
}

/**
 * GET /v2/images/{digest}/check — policy compliance / gate findings (optional tag, base_digest query params).
 */
export async function runImagePolicyCheck(
  args: ImagePolicyCheckArgs,
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
    const query = new URLSearchParams();
    if (args.tag?.trim()) {
      query.set("tag", args.tag.trim());
    }
    if (args.base_digest?.trim()) {
      query.set("base_digest", args.base_digest.trim());
    }
    const path = imagePolicyCheckPath(connection.apiVersion, digest, query);
    const data = await client.getJson<unknown>(path);
    const ctx: ToolContextFields = {
      baseUrl: connection.baseUrl,
      account: connection.account,
      apiVersion: connection.apiVersion,
      action: "image policy check",
    };
    const summaryLine = summarizePolicy(data);
    const text = formatAnchoreToolJson(ctx, summaryLine, data);
    return { content: [{ type: "text", text }] };
  } catch (err) {
    logStderrLine(`anchore_image_policy_check: ${anchoreFailureMessage(err)}`);
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

/**
 * GET /v2/images/{digest} — image analysis metadata (build-summary style fields depend on deployment).
 */
export async function runImageDetail(
  args: ImageDetailArgs,
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
    const path = imageByDigestPath(connection.apiVersion, digest);
    const { data, byteLength } = await client.getJsonWithByteLength<unknown>(
      path,
    );
    const ctx: ToolContextFields = {
      baseUrl: connection.baseUrl,
      account: connection.account,
      apiVersion: connection.apiVersion,
      action: "image detail",
    };
    const summaryLine = summarizeImageDetail(data);
    const text = formatAnchoreToolJson(ctx, summaryLine, data, {
      sizeBytes: byteLength,
    });
    return { content: [{ type: "text", text }] };
  } catch (err) {
    logStderrLine(`anchore_image_detail: ${anchoreFailureMessage(err)}`);
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
