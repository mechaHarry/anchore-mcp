import { z } from "zod";

/** HTTPS Anchore Enterprise base URL (no trailing slash required). */
const URL_ENV = "ANCHORE_URL";
/** API token (Basic auth password with username `_api_key`). */
const TOKEN_ENV = "ANCHORE_TOKEN";
/** Optional Anchore account / demarcation (`x-anchore-account`). */
const ACCOUNT_ENV = "ANCHORE_ACCOUNT";

/**
 * One Anchore deployment per MCP process. Use multiple IDE MCP entries (each with
 * its own env) when you need more than one Anchore.
 */
export type ResolvedAnchoreConnection = {
  baseUrl: string;
  username: "_api_key";
  password: string;
  account?: string;
};

function requireNonEmpty(name: string, value: string | undefined): string {
  const v = value?.trim();
  if (v === undefined || v === "") {
    throw new Error(
      `${name} is required but missing or empty. Set it in the MCP server environment (see README).`,
    );
  }
  return v;
}

const urlSchema = z
  .string()
  .min(1)
  .url()
  .refine((u) => u.startsWith("https://"), {
    message: `${URL_ENV} must be an https:// URL`,
  });

/**
 * Load Anchore connection settings from the process environment.
 * Secrets must not be committed; configure env in your MCP host (Cursor, etc.).
 */
export function loadConnectionFromEnv(): ResolvedAnchoreConnection {
  const rawUrl = requireNonEmpty(URL_ENV, process.env[URL_ENV]);
  const baseUrl = urlSchema.parse(rawUrl);
  const normalized = baseUrl.replace(/\/+$/, "");

  const password = requireNonEmpty(TOKEN_ENV, process.env[TOKEN_ENV]);
  const accountRaw = process.env[ACCOUNT_ENV]?.trim();
  const account =
    accountRaw !== undefined && accountRaw.length > 0 ? accountRaw : undefined;

  return {
    baseUrl: normalized,
    username: "_api_key",
    password,
    ...(account !== undefined ? { account } : {}),
  };
}

/** Non-secret snapshot for `anchore_connection_info` and R8-style context. */
export function getConnectionSnapshot(conn: ResolvedAnchoreConnection): {
  baseUrl: string;
  account: string | null;
} {
  return {
    baseUrl: conn.baseUrl,
    account: conn.account ?? null,
  };
}
