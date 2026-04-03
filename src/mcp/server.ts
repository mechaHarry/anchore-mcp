import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import type { ResolvedAnchoreConnection } from "../config/connection.js";
import { getConnectionSnapshot } from "../config/connection.js";
import { runListImages } from "../tools/images.js";
import { runImageVulnerabilities } from "../tools/vulnerabilities.js";

const SERVER_NAME = "anchore-mcp";
const SERVER_VERSION = "0.1.0";

/** Non-secret connection info for tools (R8 context). Exported for tests. */
export function getConnectionInfo(connection: ResolvedAnchoreConnection) {
  return getConnectionSnapshot(connection);
}

export function createMcpServer(connection: ResolvedAnchoreConnection): McpServer {
  const server = new McpServer({
    name: SERVER_NAME,
    version: SERVER_VERSION,
  });

  server.tool(
    "anchore_connection_info",
    "Show the Anchore base URL and optional account for this MCP server (non-secret). One MCP process connects to one Anchore; add another MCP entry for another deployment.",
    async () => {
      const text = JSON.stringify(getConnectionInfo(connection), null, 2);
      return {
        content: [{ type: "text", text }],
      };
    },
  );

  server.tool(
    "anchore_list_images",
    "List analyzed images from Anchore (GET /v1/images). Optional query filters depend on your Anchore version — confirm parameters in your deployment Swagger.",
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
    async (args) => runListImages(connection, args),
  );

  server.tool(
    "anchore_image_vulnerabilities",
    "List vulnerabilities for an analyzed image by digest (GET /v1/images/{image_digest}/vulnerabilities).",
    {
      image_digest: z
        .string()
        .min(1)
        .describe("Image digest, e.g. sha256:…"),
    },
    async (args) => runImageVulnerabilities(connection, args),
  );

  return server;
}

export async function main(connection: ResolvedAnchoreConnection): Promise<void> {
  const server = createMcpServer(connection);
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
