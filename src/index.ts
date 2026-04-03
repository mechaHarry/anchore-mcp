/**
 * Dynamic import so a missing `dist/` build or bad path fails with a clear stderr line
 * instead of an unhandled exception during static import.
 *
 * Avoid `process.on('uncaughtException')` here — some IDE/agent hosts manage the child
 * lifecycle and extra global handlers can interact badly with their probes.
 */
void (async () => {
  try {
    const { main } = await import("./mcp/server.js");
    await main();
  } catch (err) {
    console.error("[anchore-mcp] startup:", err);
    process.exit(1);
  }
})();
