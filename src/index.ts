/**
 * Entrypoint: dynamic import so a failure loading `mcp/server.js` (missing `dist/`, bad path)
 * is caught and printed to stderr instead of an unhandled exception during static import.
 */
function logFatal(scope: string, err: unknown): void {
  console.error(`[anchore-mcp] ${scope}:`, err);
  process.exit(1);
}

process.on("uncaughtException", (err) => {
  logFatal("uncaughtException", err);
});

process.on("unhandledRejection", (reason) => {
  logFatal("unhandledRejection", reason);
});

void (async () => {
  try {
    const { main } = await import("./mcp/server.js");
    await main();
  } catch (err) {
    logFatal("startup", err);
  }
})();
