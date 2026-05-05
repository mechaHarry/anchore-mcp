import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { ImageSbomFormatPath } from "../anchore/api-paths.js";
import { imageSbomPath } from "../anchore/api-paths.js";
import { createAnchoreClient } from "../anchore/client.js";
import { loadConnectionFromEnv } from "../config/connection.js";
import { logStderrLine } from "../logging/safe-log.js";
import type { AnchoreToolRunOptions } from "./anchore-run-options.js";
import { anchoreFailureMessage } from "./anchore-tool-error.js";
import type { ToolContextFields } from "./context.js";
import { formatAnchoreToolJson } from "./format.js";
import { resolveDigestForAnchorePath } from "./image-input.js";

const DEFAULT_MAX_RESPONSE_BYTES = 20_000_000;

export type ImageSbomFormat = "normal" | "spdx" | "cyclonedx";

export type ImageSbomArgs = {
  /** Use this or image_reference, not both. */
  image_digest?: string;
  /** Fully qualified registry/repo:tag; MCP resolves to digest (same SBOM path as digest). */
  image_reference?: string;
  /** `normal` = Syft native JSON; `spdx` / `cyclonedx` = standard interchange JSON. */
  format: ImageSbomFormat;
  /**
   * Reject responses larger than this many bytes (UTF-8) with a clear error — no silent truncation (R15).
   * Default 20_000_000. Increase only when you intend to handle very large SBOMs in the assistant context.
   */
  max_response_bytes?: number;
};

function mapToPathFormat(format: ImageSbomFormat): ImageSbomFormatPath {
  if (format === "normal") {
    return "native-json";
  }
  if (format === "spdx") {
    return "spdx-json";
  }
  return "cyclonedx-json";
}

function summarizeSbom(
  format: ImageSbomFormat,
  pathFormat: ImageSbomFormatPath,
  byteLength: number,
): string {
  const humanKb = (byteLength / 1024).toFixed(1);
  return `Retrieved ${format} SBOM (${pathFormat}) — response size ~${humanKb} KiB (${byteLength} bytes UTF-8).`;
}

/**
 * GET /v2/images/{digest}/sboms/{native-json|spdx-json|cyclonedx-json} (v2 default).
 */
export async function runImageSbom(
  args: ImageSbomArgs,
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

  const resolved = await resolveDigestForAnchorePath(
    args,
    connection,
    options,
    `image SBOM (${args.format})`,
  );
  if (!resolved.ok) {
    return resolved.result;
  }
  const { digest, resolvedFromImageReference } = resolved;

  const pathFormat = mapToPathFormat(args.format);
  const maxBytes = args.max_response_bytes ?? DEFAULT_MAX_RESPONSE_BYTES;

  try {
    const client = createAnchoreClient(connection, { fetch: options?.fetch });
    const path = imageSbomPath(connection.apiVersion, digest, pathFormat);
    const { data, byteLength } = await client.getJsonWithByteLength<unknown>(
      path,
      { maxResponseBytes: maxBytes },
    );
    const ctx: ToolContextFields = {
      baseUrl: connection.baseUrl,
      account: connection.account,
      apiVersion: connection.apiVersion,
      action: `image SBOM (${args.format})`,
      ...(resolvedFromImageReference !== undefined
        ? { resolvedFromImageReference }
        : {}),
    };
    const summaryLine = summarizeSbom(args.format, pathFormat, byteLength);
    const text = formatAnchoreToolJson(ctx, summaryLine, data, {
      sizeBytes: byteLength,
    });
    return { content: [{ type: "text", text }] };
  } catch (err) {
    logStderrLine(`anchore_image_sbom: ${anchoreFailureMessage(err)}`);
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
