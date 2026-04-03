import type { ResolvedAnchoreConnection } from "../config/connection.js";

/** Optional overrides for tool handlers (tests inject `connection`; production reads env). */
export type AnchoreToolRunOptions = {
  fetch?: typeof fetch;
  connection?: ResolvedAnchoreConnection;
};
