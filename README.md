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
        "ANCHORE_TOKEN": "your-api-token-here"
      }
    }
  }
}
```

If your Cursor build only offers URL + headers and no command field, check the docs or settings for **stdio** / **local command** MCP, or use the project/user `mcp.json` file Cursor reads so you can paste the JSON above.

## Status

Implementation follows the plan units. **Unit 2** resolves a single Anchore from **`ANCHORE_URL`**, **`ANCHORE_TOKEN`**, and optional **`ANCHORE_ACCOUNT`**, and exposes `anchore_connection_info` with non-secret metadata.
