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

For a repo-local Codex setup that other agents can reuse without committing secrets, see [examples/codex-agent-setup](examples/codex-agent-setup/README.md).

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

After `pnpm run build`:

```bash
export ANCHORE_URL=https://anchore.example.com
export ANCHORE_TOKEN=your-api-token
node dist/index.js
```

This process speaks **MCP over stdio** (stdin/stdout). It does **not** expose an HTTP URL. **Do not** put the token in repo files; pass it via the host’s MCP `env` block.

## Cursor IDE

Cursor’s MCP UI often shows **URL** and **headers** first. Those fields are for **remote** MCP servers (HTTP or SSE). **This server is local stdio** — ignore URL and headers for normal use.

Configure a **command-based** entry instead (names and paths differ by Cursor version):

1. Open MCP settings and add a server that runs a **shell command** (sometimes labeled “stdio”, “local”, or “command”).
2. **Command:** `node` (or the full path to your Node binary).
3. **Arguments:** absolute path to `dist/index.js` in your clone of this repo, e.g. `/path/to/anchore-mcp/dist/index.js`.
4. **Environment variables:** set `ANCHORE_URL`, `ANCHORE_TOKEN`, and optionally `ANCHORE_ACCOUNT`.

Example fragment for a JSON-style MCP config:

```json
{
  "mcpServers": {
    "anchore-mcp": {
      "command": "node",
      "args": ["/absolute/path/to/anchore-mcp/dist/index.js"],
      "env": {
        "ANCHORE_URL": "https://anchore.example.com",
        "ANCHORE_TOKEN": "your-api-token-here",
        "ANCHORE_ACCOUNT": "optional-account-name",
        "ANCHORE_API_VERSION": "v2"
      }
    }
  }
}
```

If your Cursor build only offers URL + headers and no command field, check the docs or settings for **stdio** / **local command** MCP, or use the project/user `mcp.json` file Cursor reads so you can paste the JSON above.

### Troubleshooting MCP startup (Cursor / agent)

- **`ANCHORE_*` at startup:** The server **no longer exits** if `ANCHORE_URL` / `ANCHORE_TOKEN` are missing. It starts so the MCP handshake can finish (including IDE trust prompts and `agent` CLI checks). Configuration is loaded when you run a tool; until then, `anchore_connection_info` returns `configured: false` and other tools return a clear configuration error.
- **Still failing to connect:** Ensure your `mcp.json` **`env`** block lists every variable you need. Cursor does **not** load your shell profile for the MCP child process.
- **`ANCHORE_URL` must be `https://...`:** Invalid URLs are rejected when a tool loads the connection (not at process start).
- **Agent terminal vs MCP:** Running `node dist/index.js` in Cursor’s **terminal** only sees variables you `export` there; the **MCP server** uses only the **`env`** block in JSON.
- **JSON syntax:** Invalid `mcp.json` (e.g. trailing commas) can prevent Cursor from loading MCP servers — validate the file.

### MCP stdin / trust race (Cursor, `agent`, etc.)

MCP over **stdio** requires the host to keep **stdin open** for the whole session. Some flows start the server **before** workspace trust finishes or **probe** the binary with a pipe that closes immediately. Then stdin hits **EOF**, the Node process exits, and you may see a hang or drop back to the shell **before** you confirm trust.

Mitigations:

1. **Trust the workspace first**, then enable or restart the MCP server / agent session.
2. Use an **absolute path** to `dist/index.js` in MCP config (wrong `cwd` → wrong relative path → crash on import; check stderr for `[anchore-mcp] startup:`).

Image list **filtering** is limited to what the tool forwards (public `fulltag` translated to v2 wire `full_tag`, or retained as v1 wire `fulltag`, plus `vulnerability_id`) and what the matching deployment OpenAPI documents for `GET /v1|/v2/images`. Do not treat registry/repository selection as a fallback `/images` filter: the policy-blocking tool uses `/v2/summaries/image-tags`, and other custom filters must be advertised by your deployment OpenAPI.

## Status

Per [docs/plans/2026-04-02-001-feat-anchore-enterprise-mcp-plan.md](docs/plans/2026-04-02-001-feat-anchore-enterprise-mcp-plan.md): **Units 1–8 are implemented** (read tools, remediation handoff + [docs/remediation-handoff-schema.md](docs/remediation-handoff-schema.md), **ESLint** + **`pnpm run check`**, [`.github/workflows/ci.yml`](.github/workflows/ci.yml)).
