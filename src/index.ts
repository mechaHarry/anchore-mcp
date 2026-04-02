import { main } from "./mcp/server.js";

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
