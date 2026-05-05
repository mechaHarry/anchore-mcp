# Codex Agent Setup Example

This example shows how to expose this Anchore MCP server to Codex from one
repository only, so another agent or LLM can ask focused questions such as:

```text
Use the anchore-mcp MCP server. Call anchore_policy_blocking_vulnerabilities
with image_repository="psf/help-site". Return only the selected image and
policy-blocking vulnerability count.
```

## Shape

Use a repo-local Codex config:

```text
your-repo/
  .codex/
    config.toml
    anchore-mcp-launcher.mjs
    anchore-mcp.env.json
```

Keep `.codex/` out of source control:

```gitignore
.codex/
```

Do not put Anchore secrets directly in `config.toml`. Some Codex inspection
commands display inline MCP `env` values. The launcher pattern keeps normal MCP
listing output free of credentials.

## `.codex/config.toml`

```toml
[mcp_servers.anchore-mcp]
command = "node"
args = ["/absolute/path/to/your-repo/.codex/anchore-mcp-launcher.mjs"]
enabled = true
startup_timeout_sec = 20
tool_timeout_sec = 300
```

## `.codex/anchore-mcp.env.json`

Use mode `0600` on this file.

```json
{
  "ANCHORE_URL": "https://anchore.example.com",
  "ANCHORE_TOKEN": "<anchore-api-token>",
  "ANCHORE_ACCOUNT": "example-account"
}
```

Optional:

```json
{
  "ANCHORE_API_VERSION": "v2",
  "ANCHORE_HTTP_TIMEOUT_MS": "30000",
  "ANCHORE_HTTP_MAX_RETRIES": "2"
}
```

## `.codex/anchore-mcp-launcher.mjs`

```js
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const envPath = path.join(__dirname, "anchore-mcp.env.json");
const serverPath = "/absolute/path/to/anchore-mcp/dist/index.js";
const extraEnv = JSON.parse(fs.readFileSync(envPath, "utf8"));

const child = spawn(process.execPath, [serverPath], {
  stdio: "inherit",
  env: { ...process.env, ...extraEnv },
});

for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => {
    if (!child.killed) child.kill(signal);
  });
}

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
  } else {
    process.exit(code ?? 1);
  }
});
```

## Build

From the Anchore MCP repo:

```bash
pnpm install
pnpm run build
```

`serverPath` in the launcher must point at the built `dist/index.js`.

## Verify Codex Sees It

From the repository where `.codex/config.toml` lives:

```bash
codex mcp list --json
```

Expected shape:

```json
{
  "name": "anchore-mcp",
  "enabled": true,
  "transport": {
    "type": "stdio",
    "command": "node",
    "args": ["/absolute/path/to/your-repo/.codex/anchore-mcp-launcher.mjs"],
    "env": null
  }
}
```

If the project is not trusted yet, trust it in Codex first. Project-local
`.codex/config.toml` is applied only for trusted projects.

## Agent Prompt

Use this kind of prompt in a fresh Codex session that starts in the configured
directory:

```text
Use the anchore-mcp MCP server. Call anchore_policy_blocking_vulnerabilities
with image_repository="psf/help-site". Do not inspect or print env/config
secrets. Return compact JSON with policyRemediationStatus, selectedImage, and
blockingVulnerabilityCount.
```

The tool returns only vulnerability records that are proven policy blockers.
It does not return broad vulnerability lists, raw policy payloads, or unrelated
SBOM data.
