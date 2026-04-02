import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const SERVER_NAME = "anchore-mcp";
const SERVER_VERSION = "0.1.0";

/** Placeholder until Unit 2 loads config from disk. Exported for tests. */
export function getProfilesSnapshot(): {
  profiles: string[];
  defaultProfile: string | null;
  note: string;
} {
  return {
    profiles: [],
    defaultProfile: null,
    note:
      "No profiles loaded yet — profile file support lands in Unit 2 (see plan).",
  };
}

export function createMcpServer(): McpServer {
  const server = new McpServer({
    name: SERVER_NAME,
    version: SERVER_VERSION,
  });

  server.tool(
    "anchore_list_profiles",
    "List configured Anchore profile names and the active default. Returns only non-secret metadata.",
    async () => {
      const text = JSON.stringify(getProfilesSnapshot(), null, 2);
      return {
        content: [{ type: "text", text }],
      };
    },
  );

  return server;
}

export async function main(): Promise<void> {
  const server = createMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
