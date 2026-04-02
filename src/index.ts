import { getDefaultConfigPath, loadConfigFile, ProfileRegistry } from "./config/profiles.js";
import { main } from "./mcp/server.js";

const resolvedPath = getDefaultConfigPath();

let loaded;
try {
  loaded = loadConfigFile(resolvedPath);
} catch (err) {
  console.error(err);
  process.exit(1);
}

const registry = new ProfileRegistry(
  loaded.config,
  loaded.resolvedPath,
  loaded.fileFound,
);

main(registry).catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
