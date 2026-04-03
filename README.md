# anchore-mcp

MCP server for **Anchore Enterprise**: named profiles, read-only CVE/image insight, SBOM and exports, and a remediation handoff bundle. See [docs/brainstorms/2026-04-02-anchore-enterprise-mcp-requirements.md](docs/brainstorms/2026-04-02-anchore-enterprise-mcp-requirements.md) and [docs/plans/2026-04-02-001-feat-anchore-enterprise-mcp-plan.md](docs/plans/2026-04-02-001-feat-anchore-enterprise-mcp-plan.md).

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

- Copy [config.example.yaml](config.example.yaml) to `~/.config/anchore-mcp/config.yaml` (Unix) or set **`ANCHORE_MCP_CONFIG`** to an absolute path of your YAML file.
- Each profile uses **`username: _api_key`** and **`passwordEnv`** naming an environment variable that holds the API token (never put the token in the YAML file).

## Run (stdio MCP)

After `pnpm run build`:

```bash
node dist/index.js
```

This process speaks **MCP over stdio** (stdin/stdout). It does **not** expose an HTTP URL. Anchore credentials are **not** MCP `headers` — they come from your profile YAML and the env vars it references (see [Configuration](#configuration)).

## Cursor IDE

Cursor’s MCP UI often shows **URL** and **headers** first. Those fields are for **remote** MCP servers (HTTP or SSE). **This server is local stdio** — ignore URL and headers for normal use.

Configure a **command-based** entry instead (names and paths differ by Cursor version):

1. Open MCP settings and add a server that runs a **shell command** (sometimes labeled “stdio”, “local”, or “command”).
2. **Command:** `node` (or the full path to your Node binary).
3. **Arguments:** absolute path to `dist/index.js` in your clone of this repo, e.g. `/path/to/anchore-mcp/dist/index.js`.
4. **Environment variables:** at minimum set the token variable your profile uses (e.g. `ANCHORE_TOKEN`), and optionally `ANCHORE_MCP_CONFIG` if the config file is not in the default location.

Example fragment for a JSON-style MCP config (adjust paths and env names to match your machine and `config.example.yaml`):

```json
{
  "mcpServers": {
    "anchore-mcp": {
      "command": "node",
      "args": ["/absolute/path/to/anchore-mcp/dist/index.js"],
      "env": {
        "ANCHORE_MCP_CONFIG": "/absolute/path/to/config.yaml",
        "ANCHORE_TOKEN": "your-api-token-here"
      }
    }
  }
}
```

If your Cursor build only offers URL + headers and no command field, check the docs or settings for **stdio** / **local command** MCP, or use the project/user `mcp.json` file Cursor reads so you can paste the JSON above.

## Status

Implementation follows the plan units. **Unit 2** loads **named profiles** from YAML (Zod-validated), **`defaultProfile`**, **`ANCHORE_MCP_CONFIG`**, and exposes `anchore_list_profiles` with non-secret metadata.
