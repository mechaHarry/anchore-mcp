import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { ProfileRegistry } from "../config/profiles.js";

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

  return server;
}

export async function main(registry: ProfileRegistry): Promise<void> {
  const server = createMcpServer(registry);
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
