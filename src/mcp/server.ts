import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import type { ResolvedAnchoreConnection } from "../config/connection.js";
import {
  getConnectionSnapshot,
  loadConnectionFromEnv,
} from "../config/connection.js";
import { runListImages } from "../tools/images.js";
import { runImageDetail, runImagePolicyCheck } from "../tools/reports.js";
import { runImageSbom } from "../tools/sbom.js";
import { runImageVulnerabilities } from "../tools/vulnerabilities.js";

const SERVER_NAME = "anchore-mcp";
const SERVER_VERSION = "0.1.0";

/** Non-secret connection info for tools (R8 context). Exported for tests. */
export function getConnectionInfo(connection: ResolvedAnchoreConnection) {
  return getConnectionSnapshot(connection);
}

export type CreateMcpServerOptions = {
  /**
   * Tests: use a fixed connection. Production omits this so env is read when each tool runs
   * (stdio handshake and trust checks can run without ANCHORE_* set).
   */
  connection?: ResolvedAnchoreConnection;
};

export function createMcpServer(options: CreateMcpServerOptions = {}): McpServer {
  const server = new McpServer({
    name: SERVER_NAME,
    version: SERVER_VERSION,
  });

  server.tool(
    "anchore_connection_info",
    "Show the Anchore base URL and optional account for this MCP server (non-secret). One MCP process connects to one Anchore; add another MCP entry for another deployment.",
    async () => {
      try {
        const c = options.connection ?? loadConnectionFromEnv();
        const text = JSON.stringify(getConnectionInfo(c), null, 2);
        return {
          content: [{ type: "text", text }],
        };
      } catch (e) {
        const text = JSON.stringify(
          {
            configured: false,
            message:
              "Anchore is not configured yet. Set ANCHORE_URL and ANCHORE_TOKEN in this MCP server's environment (see README). Trust checks may run the server without those variables.",
            detail: e instanceof Error ? e.message : String(e),
          },
          null,
          2,
        );
        return {
          content: [{ type: "text", text }],
        };
      }
    },
  );

  server.tool(
    "anchore_list_images",
    "List analyzed images (default GET /v2/images; set ANCHORE_API_VERSION=v1 for legacy /v1/images). Optional query filters depend on your Anchore build — see your deployment /v2/openapi.json.",
    {
      fulltag: z
        .string()
        .optional()
        .describe("When supported, filter by full image tag"),
      vulnerability_id: z
        .string()
        .optional()
        .describe("When supported, filter by CVE id (e.g. CVE-2024-1234)"),
    },
    async (args) => runListImages(args, { connection: options.connection }),
  );

  server.tool(
    "anchore_image_vulnerabilities",
    "List vulnerabilities for an image digest (default GET /v2/images/{digest}/vuln/all; v1 uses .../vulnerabilities). Set ANCHORE_API_VERSION if needed.",
    {
      image_digest: z
        .string()
        .min(1)
        .describe("Image digest, e.g. sha256:…"),
    },
    async (args) =>
      runImageVulnerabilities(args, { connection: options.connection }),
  );

  server.tool(
    "anchore_image_sbom",
    "Fetch SBOM JSON for an analyzed image digest. Uses GET /v2/images/{digest}/sboms/{native-json|spdx-json|cyclonedx-json} (Syft native, SPDX JSON, or CycloneDX JSON). Responses include sizeBytes (R15). Default max_response_bytes=20MB — increase explicitly for huge SBOMs; otherwise the tool fails with a clear error (no silent truncation). Confirm paths on your deployment /v2/openapi.json.",
    {
      image_digest: z
        .string()
        .min(1)
        .describe("Image digest, e.g. sha256:…"),
      format: z
        .enum(["normal", "spdx", "cyclonedx"])
        .describe(
          "normal = Syft native JSON; spdx / cyclonedx = interchange JSON variants",
        ),
      max_response_bytes: z
        .number()
        .int()
        .positive()
        .max(100_000_000)
        .optional()
        .describe(
          "Reject larger HTTP bodies (UTF-8 bytes). Default 20_000_000.",
        ),
    },
    async (args) => runImageSbom(args, { connection: options.connection }),
  );

  server.tool(
    "anchore_image_policy_check",
    "Policy compliance evaluation for an image (GET /v2/images/{digest}/check). Pass tag when your Anchore version requires it. Optional base_digest for base-image comparison. Returns gate findings — see Anchore policy docs.",
    {
      image_digest: z
        .string()
        .min(1)
        .describe("Image digest, e.g. sha256:…"),
      tag: z
        .string()
        .optional()
        .describe("Full image tag if required, e.g. docker.io/library/nginx:latest"),
      base_digest: z
        .string()
        .optional()
        .describe("Optional base image digest for comparison checks"),
    },
    async (args) =>
      runImagePolicyCheck(args, { connection: options.connection }),
  );

  server.tool(
    "anchore_image_detail",
    "Single image analysis record (GET /v2/images/{digest}) — tags, distro, layers, status; exact fields depend on deployment. Includes sizeBytes for the JSON payload (R15).",
    {
      image_digest: z
        .string()
        .min(1)
        .describe("Image digest, e.g. sha256:…"),
    },
    async (args) => runImageDetail(args, { connection: options.connection }),
  );

  return server;
}

/**
 * Stdio MCP: the host must keep stdin open for the lifetime of the session.
 * See README “MCP stdin / trust race”. Avoid extra stderr noise here — some hosts treat
 * any stderr as a failed MCP child and can leave agent/MCP UI stuck until restart.
 */
export async function main(): Promise<void> {
  process.stdin.resume();

  const server = createMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
