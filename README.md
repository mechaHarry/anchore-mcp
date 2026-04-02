# anchore-mcp

MCP server for **Anchore Enterprise**: named profiles, read-only CVE/image insight, SBOM and exports, and a remediation handoff bundle. See [docs/brainstorms/2026-04-02-anchore-enterprise-mcp-requirements.md](docs/brainstorms/2026-04-02-anchore-enterprise-mcp-requirements.md) and [docs/plans/2026-04-02-001-feat-anchore-enterprise-mcp-plan.md](docs/plans/2026-04-02-001-feat-anchore-enterprise-mcp-plan.md).

## Prerequisites

- **Node.js** 20 or newer (LTS). Primary development targets **Node 25.x** (see `.nvmrc` — currently `25.9.0`).
- **npm** or **pnpm** — either works; lockfile is **npm** (`package-lock.json`). If you use pnpm, run `pnpm install` and it will respect `package.json`; consider committing `pnpm-lock.yaml` only if the team standardizes on pnpm.

## Setup

```bash
npm install
npm run build
npm test
```

With **pnpm**:

```bash
pnpm install
pnpm run build
pnpm test
```

## Run (stdio MCP)

After `npm run build`:

```bash
node dist/index.js
```

Configure your AI client to launch this command for the MCP server (stdio transport).

## Status

Implementation follows the plan units. **Unit 1** provides a minimal stdio server and the `anchore_list_profiles` smoke tool (empty profiles until profile config lands in Unit 2).
