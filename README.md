# anchore-mcp

MCP server for **Anchore Enterprise**: named profiles, read-only CVE/image insight, SBOM and exports, and a remediation handoff bundle. See [docs/brainstorms/2026-04-02-anchore-enterprise-mcp-requirements.md](docs/brainstorms/2026-04-02-anchore-enterprise-mcp-requirements.md) and [docs/plans/2026-04-02-001-feat-anchore-enterprise-mcp-plan.md](docs/plans/2026-04-02-001-feat-anchore-enterprise-mcp-plan.md).

## Prerequisites

- **Node.js** 20+ (see `.nvmrc`)

## Setup

```bash
npm install
npm run build
npm test
```

## Run (stdio MCP)

After `npm run build`:

```bash
node dist/index.js
```

Configure your AI client to launch this command for the MCP server (stdio transport).

## Status

Implementation follows the plan units. **Unit 1** provides a minimal stdio server and the `anchore_list_profiles` smoke tool (empty profiles until profile config lands in Unit 2).
