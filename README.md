# anchore-mcp

MCP server for **Anchore Enterprise**: read-only CVE/image insight, SBOM and exports, and a remediation handoff bundle. See [docs/brainstorms/2026-04-02-anchore-enterprise-mcp-requirements.md](docs/brainstorms/2026-04-02-anchore-enterprise-mcp-requirements.md) and [docs/plans/2026-04-02-001-feat-anchore-enterprise-mcp-plan.md](docs/plans/2026-04-02-001-feat-anchore-enterprise-mcp-plan.md).

**Compounded learnings:** working notes live in [MEMORY.md](MEMORY.md); durable, searchable write-ups live under [docs/solutions/](docs/solutions/). Rules for moving from one to the other are in [AGENTS.md](AGENTS.md#knowledge-flow).

## Prerequisites

- **Node.js** 20+ (see `.nvmrc` for the version used in development).
- [**pnpm**](https://pnpm.io/) — lockfile is `pnpm-lock.yaml`. Use [Corepack](https://nodejs.org/api/corepack.html) (`corepack enable`) to install the version from `package.json`’s `packageManager` field.

## Setup

```bash
pnpm install
pnpm run build
pnpm test
```

For the full gate used in CI (lint, typecheck, build, tests):

```bash
pnpm run check
```

## CI

On GitHub, **push** and **pull_request** workflows run [`.github/workflows/ci.yml`](.github/workflows/ci.yml) (`pnpm install --frozen-lockfile` → `pnpm run check`). Without Actions, run `pnpm run check` locally before merging.

## Configuration

Each MCP process talks to **one** Anchore deployment. Set environment variables (see [env.example](env.example)):

| Variable | Required | Description |
|----------|----------|-------------|
| `ANCHORE_URL` | Yes | HTTPS base URL of Anchore Enterprise (e.g. `https://anchore.company.com`) |
| `ANCHORE_TOKEN` | Yes | API token (sent as Basic auth with username `_api_key`) |
| `ANCHORE_ACCOUNT` | No | Optional account name (`x-anchore-account`) when your deployment uses it |
| `ANCHORE_API_VERSION` | No | `v2` (default) or `v1`. Enterprise 5+ expects **v2** paths (`/v2/images`, etc.). Use `v1` only for legacy installs. Confirm with `https://<host>/v2/openapi.json` on your deployment. |
| `ANCHORE_HTTP_MAX_RETRIES` | No | Extra attempts after a failed **idempotent GET** (default `2`). Retries **transient** HTTP statuses (429, 502–504) and network errors, with exponential backoff + jitter. **Timeouts are not retried.** |
| `ANCHORE_HTTP_RETRY_BASE_MS` | No | Backoff base in ms (default `300`). |
| `ANCHORE_HTTP_RETRY_MAX_MS` | No | Backoff cap in ms (default `8000`). |

Need **multiple** Anchore deployments? Add **multiple** MCP server entries in your IDE, each with its own `command`/`args` and **different** `env` (different `ANCHORE_URL` and token).

## Minimal Codex setup (all read-only tools, no prompts)

This is a local **stdio** MCP server. The eight tools enabled below only perform Anchore `GET` requests. The exact allowlist makes the setup fail closed: a future tool is disabled until an operator audits it, adds it to `enabled_tools`, and adds an explicit approval stanza. Keep the alias `anchore-mcp` identical in every TOML table; if you rename it, rename every occurrence.

### 1. Build

From the current `anchore-mcp` clone:

```bash
pnpm install
pnpm run check
```

`pnpm run check` rebuilds `dist/index.js` and runs lint, typecheck, and tests.

### 2. Find and verify absolute paths

Use an executable Node path, not `dist/index.js`, as `command`. A bare `node` depends on the MCP child's `PATH` and is less reliable.

```bash
command -v node
test -d /absolute/path/to/anchore-mcp
test -x /absolute/path/to/node
test -f /absolute/path/to/anchore-mcp/dist/index.js
```

The Node path, `dist/index.js` path, and `cwd` must be absolute and must reference the current clone rather than an old checkout.

### 3. Add config

Add this to the other Codex setup's trusted `config.toml`, replacing the absolute path placeholders:

```toml
[mcp_servers.anchore-mcp]
command = "/absolute/path/to/node"
args = ["/absolute/path/to/anchore-mcp/dist/index.js"]
cwd = "/absolute/path/to/anchore-mcp"
enabled = true
startup_timeout_sec = 20
tool_timeout_sec = 300
enabled_tools = [
  "anchore_connection_info",
  "anchore_list_images",
  "anchore_image_vulnerabilities",
  "anchore_image_sbom",
  "anchore_image_policy_check",
  "anchore_policy_blocking_vulnerabilities",
  "anchore_image_detail",
  "anchore_remediation_handoff",
]

[mcp_servers.anchore-mcp.tools.anchore_connection_info]
approval_mode = "approve"

[mcp_servers.anchore-mcp.tools.anchore_list_images]
approval_mode = "approve"

[mcp_servers.anchore-mcp.tools.anchore_image_vulnerabilities]
approval_mode = "approve"

[mcp_servers.anchore-mcp.tools.anchore_image_sbom]
approval_mode = "approve"

[mcp_servers.anchore-mcp.tools.anchore_image_policy_check]
approval_mode = "approve"

[mcp_servers.anchore-mcp.tools.anchore_policy_blocking_vulnerabilities]
approval_mode = "approve"

[mcp_servers.anchore-mcp.tools.anchore_image_detail]
approval_mode = "approve"

[mcp_servers.anchore-mcp.tools.anchore_remediation_handoff]
approval_mode = "approve"
```

Do not set `command` to `dist/index.js`. The explicit `enabled_tools` list is intentional; consciously update both the allowlist and approval stanzas only after auditing a new tool as read-only.

### 4. Provide secrets safely

Real calls require `ANCHORE_URL` and `ANCHORE_TOKEN`. `ANCHORE_ACCOUNT` is optional; `ANCHORE_API_VERSION` is optional and defaults to `v2` (recommended for Enterprise 5+). Optional retry tuning is limited to `ANCHORE_HTTP_MAX_RETRIES`, `ANCHORE_HTTP_RETRY_BASE_MS`, and `ANCHORE_HTTP_RETRY_MAX_MS`.

Do not commit credentials or paste them into diagnostics. Prefer the [gitignored launcher plus mode-`0600` environment-file pattern](examples/codex-agent-setup/README.md) instead of inline secret TOML. When using that pattern, change only `args` to the absolute launcher path; the launcher starts the same absolute `dist/index.js` path.

### 5. Verify non-secret transport

From the directory whose Codex config contains this server:

```bash
codex mcp get anchore-mcp --json | jq '{name, enabled, disabled_reason, transport: {type: .transport.type, command: .transport.command, args: .transport.args, cwd: .transport.cwd}, enabled_tools, disabled_tools, startup_timeout_sec, tool_timeout_sec}'
```

Confirm the filtered output shows `enabled: true`, the intended absolute paths, and the exact eight-item `enabled_tools` list. Do not print the raw result or environment fields. `codex mcp get` does not expose per-tool `approval_mode`; inspect the eight tool stanzas in trusted TOML without printing adjacent secret configuration.

### 6. Smoke test

Start a fresh Codex session in the configured, trusted directory and try:

```text
Use the anchore-mcp MCP server. Call anchore_connection_info. Return only
whether the connection is configured, its API version, and its non-secret URL.
Do not inspect or print MCP configuration or environment values.
```

Then verify repository-smart selection:

```text
Use the anchore-mcp MCP server. Call anchore_policy_blocking_vulnerabilities
with image_registry="registry.example.com" and image_repository="team/app".
Return the selected image and a compact policy-blocking vulnerability summary.
Do not inspect or print MCP configuration or environment values.
```

### Image digest vs reference

Anchore’s per-image HTTP routes use the **digest** in the path (`/v2/images/{digest}/…`). For convenience, digest-keyed tools also accept **`image_reference`**: a fully qualified tagged image string (`registry/repository:tag`, e.g. `docker.io/library/nginx:latest`). With the default v2 API, the MCP queries `GET /v2/images?full_tag=…`; legacy v1 uses `GET /v1/images?fulltag=…`. The backend filter is only a narrowing hint: the MCP uses a digest only when the returned row contains exact local evidence for the requested reference. If bounded evidence inspection cannot finish, resolution reports `enumeration_incomplete` instead of `no_match`. Short names like `nginx:latest` are rejected; use a registry-qualified reference.

- Provide **exactly one** of `image_digest` or `image_reference` (not both, not neither).
- **`anchore_image_policy_check`** and **`anchore_remediation_handoff`** still have an optional **`tag`** parameter for Anchore’s `/check` query when your deployment requires it — that is separate from `image_reference` and is never auto-filled from it.
- **`anchore_list_images`** merges paged list responses until the deployment indicates there is no next page. If internal caps stop the walk early, the tool JSON may include `listEnumerationIncomplete` / `listEnumerationReason`. Resolution uses its own caps and may return `imageReferenceResolution` with `enumeration_incomplete` when the catalog cannot be fully scanned.
- **List filters:** `anchore_list_images` keeps `fulltag` as a public convenience input. It sends **`full_tag`** to `GET /v2/images` and **`fulltag`** to legacy `GET /v1/images`. You can also pass `vulnerability_id` or **`list_query`**, a map of query parameter names to string values. Allowed `list_query` keys come from a small built-in set plus the `in: query` parameters defined for `GET /v1|/v2/images` in your deployment OpenAPI (fetched when `list_query` is non-empty, then cached). Unknown keys are dropped and noted in the summary line. The built-in fallback does **not** assume that `registry`, `repository`, or `repo` filter `/images`; only a deployment OpenAPI that advertises them can allow them there.

### Policy-blocking vulnerabilities

`anchore_policy_blocking_vulnerabilities` is intended for downstream agents that need the minimal vulnerability set whose remediation would change Anchore policy from red to green.

Inputs accept exactly one image locator:

- `image_digest`
- `image_reference` (`registry/repository:tag`, exact tagged image)
- `image_registry` plus `image_repository` (`registry` plus `repository`, newest analyzed tag)

The registry/repository pair is supported only by this policy-blocking tool. In v2 it calls the verified `GET /v2/summaries/image-tags?registry=…&repository=…` route directly. In v1 it calls `/v1/summaries/image-tags` only when `/v1/openapi.json` explicitly advertises a prefixed or unprefixed `GET` path with direct `registry` and `repository` query parameters; otherwise the tool returns a static unsupported error without trying the route. `image_repository` never includes the registry or tag and cannot be supplied alone.

Newest-image timestamp trust is specific to `anchore_policy_blocking_vulnerabilities`, which selects the newest image for both `image_reference` and registry/repository locators. Every exact matching row that has a digest must also have a reliable analysis timestamp (`analyzed_at` or an accepted equivalent). If any such candidate has a missing, invalid, or untrusted timestamp, or if the newest timestamp is tied across digests, selection fails rather than guessing. A matching row without a digest cannot be selected and may be ignored. Other digest-keyed tools use the shared exact-reference resolver above; it does not choose newest and does not use timestamps.

When the selected image has a full tag, the tool uses that reference as Anchore `/check` `tag` context unless `tag` is supplied explicitly. This keeps the HTTP path digest-centric while avoiding a second lookup for deployments that require tag context during policy evaluation.

The tool calls Anchore policy check first. If policy is already green, it returns `policyRemediationStatus: "already_green"` with an empty `blockingVulnerabilities` list. If policy is red, it returns only compact vulnerabilities that can be joined to blocking policy findings by exact CVE/vulnerability id or exact package identity. It does not return unrelated policy findings, broad high/critical vulnerability lists, raw policy or vulnerability payloads, or SBOM-inferred file paths.

## Run (stdio MCP)

After `pnpm run build`, load `ANCHORE_URL` and `ANCHORE_TOKEN` into the current
shell from your approved secret manager, then run:

```bash
node dist/index.js
```

This process speaks **MCP over stdio** (stdin/stdout). It does **not** expose an HTTP URL. Do not put tokens in repo files or command history. For Codex, use the canonical [minimal setup](#minimal-codex-setup-all-read-only-tools-no-prompts) and its secure launcher pattern rather than inline host environment fields.

## Cursor IDE

Cursor’s MCP UI often shows **URL** and **headers** first. Those fields are for **remote** MCP servers (HTTP or SSE). **This server is local stdio** — ignore URL and headers for normal use.

Configure a **command-based** entry instead (names and paths differ by Cursor version). Keep the Cursor config, launcher, and environment file gitignored; set both the config and environment file to mode `0600`. MCP diagnostics can expose inline `env` values, so use the [launcher and separate environment-file pattern](examples/codex-agent-setup/README.md) and adapt its private `.codex/` paths for Cursor.

1. Open MCP settings and add a server that runs a **shell command** (sometimes labeled “stdio”, “local”, or “command”).
2. **Command:** the absolute path to your Node binary. A bare `node` works only when the MCP child process's `PATH` contains Node.
3. **Arguments:** the absolute path to your private launcher file.
4. **Environment variables:** load them from the launcher's separate, mode-`0600` environment file; do not put them inline in the Cursor MCP JSON.

Cursor-only transport example (no credentials):

```json
{
  "mcpServers": {
    "anchore-mcp": {
      "command": "/absolute/path/to/node",
      "args": ["/absolute/path/to/private/anchore-mcp-launcher.mjs"]
    }
  }
}
```

Before opening Cursor, run `chmod 600` on its gitignored `mcp.json` and environment file. If your Cursor build only offers URL + headers and no command field, check the docs or settings for **stdio** / **local command** MCP, or use the protected project/user `mcp.json` file Cursor reads.

### Troubleshooting MCP startup (Cursor / agent)

- **`ANCHORE_*` at startup:** The server **no longer exits** if `ANCHORE_URL` / `ANCHORE_TOKEN` are missing. It starts so the MCP handshake can finish (including IDE trust prompts and `agent` CLI checks). Configuration is loaded when you run a tool; until then, `anchore_connection_info` returns `configured: false` and other tools return a clear configuration error.
- **Still failing to connect:** Ensure the private launcher reads the intended mode-`0600` environment file. Cursor does **not** load your shell profile for the MCP child process.
- **`ANCHORE_URL` must be `https://...`:** Invalid URLs are rejected when a tool loads the connection (not at process start).
- **Agent terminal vs MCP:** Running `node dist/index.js` in Cursor’s **terminal** sees that terminal's environment; the configured MCP child receives the environment supplied by its private launcher.
- **JSON syntax:** Invalid `mcp.json` (e.g. trailing commas) can prevent Cursor from loading MCP servers — validate the file.

### MCP stdin / trust race (Cursor, `agent`, etc.)

MCP over **stdio** requires the host to keep **stdin open** for the whole session. Some flows start the server **before** workspace trust finishes or **probe** the binary with a pipe that closes immediately. Then stdin hits **EOF**, the Node process exits, and you may see a hang or drop back to the shell **before** you confirm trust.

Mitigations:

1. **Trust the workspace first**, then enable or restart the MCP server / agent session.
2. Use an **absolute path** to `dist/index.js` in MCP config (wrong `cwd` → wrong relative path → crash on import; check stderr for `[anchore-mcp] startup:`).

Image list **filtering** is limited to what the tool forwards (public `fulltag` translated to v2 wire `full_tag`, or retained as v1 wire `fulltag`, plus `vulnerability_id`) and what the matching deployment OpenAPI documents for `GET /v1|/v2/images`. Do not treat registry/repository selection as a fallback `/images` filter: the policy-blocking tool uses `/v2/summaries/image-tags`, and other custom filters must be advertised by your deployment OpenAPI.

## Status

Per [docs/plans/2026-04-02-001-feat-anchore-enterprise-mcp-plan.md](docs/plans/2026-04-02-001-feat-anchore-enterprise-mcp-plan.md): **Units 1–8 are implemented** (read tools, remediation handoff + [docs/remediation-handoff-schema.md](docs/remediation-handoff-schema.md), **ESLint** + **`pnpm run check`**, [`.github/workflows/ci.yml`](.github/workflows/ci.yml)).
