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

Configure your AI client to launch this command for the MCP server (stdio transport).

## Status

Implementation follows the plan units. **Unit 2** loads **named profiles** from YAML (Zod-validated), **`defaultProfile`**, **`ANCHORE_MCP_CONFIG`**, and exposes `anchore_list_profiles` with non-secret metadata.
