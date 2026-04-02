import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import type { ProfileRegistry } from "../config/profiles.js";
import { runListImages } from "../tools/images.js";
import { runImageVulnerabilities } from "../tools/vulnerabilities.js";

const SERVER_NAME = "anchore-mcp";
const SERVER_VERSION = "0.1.0";

/** Non-secret profile listing for tools (R8 context). Exported for tests. */
export function getProfilesSnapshot(registry: ProfileRegistry) {
  return registry.getPublicSnapshot();
}

export function createMcpServer(registry: ProfileRegistry): McpServer {
  const server = new McpServer({
    name: SERVER_NAME,
    version: SERVER_VERSION,
  });

  server.tool(
    "anchore_list_profiles",
    "List configured Anchore profile names and the active default. Returns only non-secret metadata.",
    async () => {
      const text = JSON.stringify(getProfilesSnapshot(registry), null, 2);
      return {
        content: [{ type: "text", text }],
      };
    },
  );

  server.tool(
    "anchore_list_images",
    "List analyzed images from Anchore (GET /v1/images). Optional query filters depend on your Anchore version — confirm parameters in your deployment Swagger.",
    {
      profile: z
        .string()
        .optional()
        .describe("Profile name; defaults to defaultProfile in config"),
      fulltag: z
        .string()
        .optional()
        .describe("When supported, filter by full image tag"),
      vulnerability_id: z
        .string()
        .optional()
        .describe("When supported, filter by CVE id (e.g. CVE-2024-1234)"),
    },
    async (args) => runListImages(registry, args),
  );

  server.tool(
    "anchore_image_vulnerabilities",
    "List vulnerabilities for an analyzed image by digest (GET /v1/images/{image_digest}/vulnerabilities).",
    {
      image_digest: z
        .string()
        .min(1)
        .describe("Image digest, e.g. sha256:…"),
      profile: z.string().optional().describe("Profile name; defaults to defaultProfile"),
    },
    async (args) => runImageVulnerabilities(registry, args),
  );

  return server;
}

export async function main(registry: ProfileRegistry): Promise<void> {
  const server = createMcpServer(registry);
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
