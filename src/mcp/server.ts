import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import type { ResolvedAnchoreConnection } from "../config/connection.js";
import {
  getConnectionSnapshot,
  loadConnectionFromEnv,
} from "../config/connection.js";
import { runListImages } from "../tools/images.js";
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

  return server;
}

/**
 * Stdio MCP: the host must keep stdin open for the lifetime of the session. Some clients
 * close the pipe briefly during workspace-trust or probe flows — the process may then exit
 * before you see a prompt. See README “MCP stdin / trust race”.
 */
export async function main(): Promise<void> {
  // Paused stdin is common; without flowing mode some hosts never deliver bytes.
  process.stdin.resume();

  process.stdin.once("end", () => {
    console.error(
      "[anchore-mcp] stdin closed (EOF). The MCP host ended this pipe — often before initialize if trust or connection setup is still pending. Retry after trust, or verify your MCP command uses a built `dist/index.js` path.",
    );
  });

  const server = createMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
