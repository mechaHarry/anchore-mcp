# Agent guidance — anchore-mcp

Local **stdio MCP server** for **Anchore Enterprise** (read-only: images, vulnerabilities, SBOM, policy check, image detail, **remediation handoff**). One **HTTPS Anchore deployment per MCP process** — multiple backends = **multiple MCP entries** in the IDE, each with its own `env`.

- Remediation handoff schema: [docs/remediation-handoff-schema.md](docs/remediation-handoff-schema.md)

## Sources of truth

- Requirements / scope: [docs/brainstorms/2026-04-02-anchore-enterprise-mcp-requirements.md](docs/brainstorms/2026-04-02-anchore-enterprise-mcp-requirements.md)
- Implementation plan & units: [docs/plans/2026-04-02-001-feat-anchore-enterprise-mcp-plan.md](docs/plans/2026-04-02-001-feat-anchore-enterprise-mcp-plan.md)
- API route research: [docs/research/anchore-api-notes.md](docs/research/anchore-api-notes.md)
- Institutional fixes (searchable): [docs/solutions/](docs/solutions/) (e.g. Anchore integration learnings)

## Architecture (current)

| Area | Role |
|------|------|
| `src/index.ts` | Entry: dynamic `import("./mcp/server.js")`, catch startup errors → `[anchore-mcp] startup:` on stderr. **No** global `uncaughtException` handlers (avoid interfering with IDE child probes). |
| `src/mcp/server.ts` | `McpServer` + `StdioServerTransport`; registers tools. |
| `src/config/connection.ts` | `loadConnectionFromEnv()` → `ANCHORE_URL`, `ANCHORE_TOKEN`, optional `ANCHORE_ACCOUNT`, `ANCHORE_API_VERSION` (`v2` default). |
| `src/anchore/client.ts` | `fetch` + Basic auth (`_api_key` + token), optional `x-anchore-account`. |
| `src/anchore/api-paths.ts` | Versioned REST paths: **v2** vs **v1**. |
| `src/tools/*` | Tools call Anchore; `formatAnchoreToolJson` for R8 + R14; SBOM / image detail / **remediation handoff** include **sizeBytes** (R15). Handoff: `remediation-handoff.ts` + [docs/remediation-handoff-schema.md](docs/remediation-handoff-schema.md). |
| `src/pii/*`, `src/logging/safe-log.ts` | R14 mask/warn; R13 stderr redaction / line cap. |

**Lazy config:** Connection is **not** loaded at process start. Missing `ANCHORE_*` does **not** exit the process — the MCP handshake can complete (trust / probes). Env is read when a tool runs (or `anchore_connection_info`).

## Environment variables

| Variable | Notes |
|----------|--------|
| `ANCHORE_URL` | Required for real calls. **HTTPS only** (validated when connection loads). |
| `ANCHORE_TOKEN` | API token (Basic password; user `_api_key`). |
| `ANCHORE_ACCOUNT` | Optional `x-anchore-account`. |
| `ANCHORE_API_VERSION` | `v2` (default) or `v1`. Enterprise 5+ uses explicit **`/v2/...`** paths; old `/v1/images` without v2 can return non-JSON or 404. |

See [env.example](env.example) and [README.md](README.md).

## Anchore REST API version (critical)

- **Default is v2:** `GET /v2/images`, `GET /v2/images/{digest}/vuln/all` (not `.../vulnerabilities`).
- List responses may use **`items`** (v2) or **`images`** (v1-style) — summarizers handle both.
- **Source of truth per deployment:** `https://<host>/v2/openapi.json`

## MCP / stdio invariants

- **stdout:** MCP JSON-RPC only. Never `console.log` to stdout.
- **stderr:** Operational logs only; use `logStderrLine` / `redactSecrets` from `src/logging/safe-log.ts`. Do not dump full tool JSON bodies to stderr (R13).
- **Entrypoint:** Keep startup minimal — avoid extra stderr during host probes; **`stdin.resume()`** before `server.connect()` helps some hosts.

## R8 / R14 (tool results)

- **R8:** Tool payloads include `context` (baseUrl, account?, `apiVersion`, action, `summaryLine`) plus `anchore` JSON and masked `summary` + `warnings`.
- **R14:** Use `prepareTextualToolText` for free-form prose only. JSON returned to the client is **not** masked; it must **not** be written wholesale to stderr.

## Cursor / IDE MCP

- This server is **stdio** (`command` + `args` + `env`). **Not** an HTTP URL + headers entry.
- The MCP child receives **only** variables in the JSON **`env`** block — not the interactive shell’s `export`.
- Use an **absolute path** to `dist/index.js` after `pnpm run build`.

## Testing & build

```bash
pnpm install && pnpm run build && pnpm test
```

Unit tests inject `connection` via `createMcpServer({ connection })` / tool `options.connection` so they do not depend on real env.

## Security

- No secrets in source or committed config. Tokens only via env / host MCP `env`.
- Treat [test.sh](test.sh) and similar as **local only** (gitignored if present).

## Plan status (when this file was written)

Units **1–7** implemented (connection, client, PII/safe logging, images/vulns, **SBOM** + policy + image detail, **v2** paths, **remediation handoff** + schema doc). **Unit 8** (CI workflow / optional lint script) per the plan — update this section as units land.

## What we learned (operational)

1. **Defer `loadConnectionFromEnv()`** until tool time so trust/probe flows do not require credentials at process start.
2. **Do not register** global `uncaughtException` / `unhandledRejection` in `index.ts` for MCP — some hosts mis-handle the child lifecycle.
3. **Avoid noisy stderr** on stdin EOF during probes — hosts may treat stderr as MCP failure.
4. **Enterprise 5+** expects explicit **`/v2/...`**; using `/v1/images` against a v2 deployment often yields HTML or non-JSON errors.
5. **`agent ls` / Cursor agent:** If behavior breaks **only** when this MCP block is present, treat as **host + this server interaction** (validate JSON, absolute `dist` path, restart IDE). Removed misleading README claims that `agent ls` stayed broken after removing the server — that was not observed.
6. **Image SBOM v2 path segment:** Use **`/v2/images/{digest}/sboms/{format}`** (plural **`sboms`**). **`/sbom/`** (singular) can yield **HTTP 400**. Source-repo SBOM URLs in Anchore docs may still use singular `sbom` under `/v2/sources/...` — do not assume parity. See [docs/research/anchore-api-notes.md](docs/research/anchore-api-notes.md) and [docs/solutions/integration-issues/2026-04-02-anchore-v2-image-sbom-sboms-path.md](docs/solutions/integration-issues/2026-04-02-anchore-v2-image-sbom-sboms-path.md).

When extending tools, follow existing patterns in `src/tools/`, keep Zod tool schemas, and extend `docs/research/anchore-api-notes.md` when routes change.
