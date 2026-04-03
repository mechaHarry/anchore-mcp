import { loadConnectionFromEnv } from "./config/connection.js";
import { main } from "./mcp/server.js";

let connection;
try {
  connection = loadConnectionFromEnv();
} catch (err) {
  console.error(err);
  process.exit(1);
}

main(connection).catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
