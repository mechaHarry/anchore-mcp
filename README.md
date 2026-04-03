# anchore-mcp

MCP server for **Anchore Enterprise**: read-only CVE/image insight, SBOM and exports, and a remediation handoff bundle. See [docs/brainstorms/2026-04-02-anchore-enterprise-mcp-requirements.md](docs/brainstorms/2026-04-02-anchore-enterprise-mcp-requirements.md) and [docs/plans/2026-04-02-001-feat-anchore-enterprise-mcp-plan.md](docs/plans/2026-04-02-001-feat-anchore-enterprise-mcp-plan.md).

## Prerequisites

- **Node.js** 20+ (see `.nvmrc` for the version used in development).
- [**pnpm**](https://pnpm.io/) — lockfile is `pnpm-lock.yaml`. Use [Corepack](https://nodejs.org/api/corepack.html) (`corepack enable`) to install the version from `package.json`’s `packageManager` field.

## Setup

```bash
pnpm install
pnpm run build
pnpm test
```

## Configuration

Each MCP process talks to **one** Anchore deployment. Set environment variables (see [env.example](env.example)):

| Variable | Required | Description |
|----------|----------|-------------|
| `ANCHORE_URL` | Yes | HTTPS base URL of Anchore Enterprise (e.g. `https://anchore.company.com`) |
| `ANCHORE_TOKEN` | Yes | API token (sent as Basic auth with username `_api_key`) |
| `ANCHORE_ACCOUNT` | No | Optional account name (`x-anchore-account`) when your deployment uses it |
| `ANCHORE_API_VERSION` | No | `v2` (default) or `v1`. Enterprise 5+ expects **v2** paths (`/v2/images`, etc.). Use `v1` only for legacy installs. Confirm with `https://<host>/v2/openapi.json` on your deployment. |

Need **multiple** Anchore deployments? Add **multiple** MCP server entries in your IDE, each with its own `command`/`args` and **different** `env` (different `ANCHORE_URL` and token).

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

Image list **filtering** is limited to what the tool forwards (`fulltag`, `vulnerability_id`) and what your Anchore **`/v2/openapi.json`** documents for `GET /v2/images`. There is no generic substring filter in the API in many deployments; tighter server-side filters are a follow-up (extra query parameters from your OpenAPI spec).

## Status

Per [docs/plans/2026-04-02-001-feat-anchore-enterprise-mcp-plan.md](docs/plans/2026-04-02-001-feat-anchore-enterprise-mcp-plan.md): **Units 1–6 are implemented** (images, vulnerabilities, **SBOM** formats, policy check, image detail, **R15** size metadata). **Next is Unit 7** — remediation handoff tool and schema doc.
