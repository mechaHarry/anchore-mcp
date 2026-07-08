# Codex Agent Setup Example

This example shows how to expose this Anchore MCP server to Codex from one
repository only, so another agent or LLM can ask focused questions such as:

```text
Use the anchore-mcp MCP server. Call anchore_policy_blocking_vulnerabilities
with image_registry="containers.example.com" and
image_repository="psf/help-site". Return only the selected image and
policy-blocking vulnerability count. The tool selects the newest analyzed tag
for that exact registry/repository pair.
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
command = "/absolute/path/to/node"
args = ["/absolute/path/to/your-repo/.codex/anchore-mcp-launcher.mjs"]
cwd = "/absolute/path/to/your-repo"
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

`command` must be an executable Node binary or launcher; never set it to
`dist/index.js`. `command = "node"` works only when the MCP child process's
`PATH` contains Node, so an absolute Node path is more reliable. Keep `args`
and `cwd` aligned with the current clone rather than an old or moved checkout.
Keep the alias `anchore-mcp` identical in every table. The exact `enabled_tools`
allowlist is fail closed: a future tool remains disabled until it is audited as
read-only and consciously added to both the allowlist and an approval stanza.

## `.codex/anchore-mcp.env.json`

Use mode `0600` on this file.

```bash
chmod 600 .codex/anchore-mcp.env.json
```

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
  "ANCHORE_HTTP_MAX_RETRIES": "2",
  "ANCHORE_HTTP_RETRY_BASE_MS": "300",
  "ANCHORE_HTTP_RETRY_MAX_MS": "8000"
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
Run `pnpm run build` after source changes so that file is current.
The required secret keys are `ANCHORE_URL` and `ANCHORE_TOKEN`.
`ANCHORE_ACCOUNT` and `ANCHORE_API_VERSION` are optional; use `v2` unless a
legacy deployment requires `v1`.

Validate the executable, launcher, and server paths without reading the secret
file:

```bash
test -x /absolute/path/to/node
test -f /absolute/path/to/your-repo/.codex/anchore-mcp-launcher.mjs
test -f /absolute/path/to/anchore-mcp/dist/index.js
```

## Verify Codex Sees It

From the repository where `.codex/config.toml` lives:

Inspect only non-secret fields:

```bash
codex mcp get anchore-mcp --json | jq '{name, enabled, disabled_reason, transport: {type: .transport.type, command: .transport.command, args: .transport.args, cwd: .transport.cwd}, enabled_tools, disabled_tools, startup_timeout_sec, tool_timeout_sec}'
```

This filtered command cannot verify per-tool `approval_mode`; Codex 0.142.5
does not expose it in `mcp get` JSON. Inspect the specific tool stanza in your
trusted TOML directly, without printing adjacent environment configuration.
Never print or paste raw MCP configuration or environment fields; they may
contain tokens.

Expected shape:

```json
{
  "name": "anchore-mcp",
  "enabled": true,
  "disabled_reason": null,
  "transport": {
    "type": "stdio",
    "command": "/absolute/path/to/node",
    "args": ["/absolute/path/to/your-repo/.codex/anchore-mcp-launcher.mjs"],
    "cwd": "/absolute/path/to/your-repo"
  },
  "enabled_tools": [
    "anchore_connection_info",
    "anchore_list_images",
    "anchore_image_vulnerabilities",
    "anchore_image_sbom",
    "anchore_image_policy_check",
    "anchore_policy_blocking_vulnerabilities",
    "anchore_image_detail",
    "anchore_remediation_handoff"
  ],
  "disabled_tools": null,
  "startup_timeout_sec": 20.0,
  "tool_timeout_sec": 300.0
}
```

If the project is not trusted yet, trust it in Codex first. Project-local
`.codex/config.toml` is applied only for trusted projects.

## Agent Prompt

Use this kind of prompt in a fresh Codex session that starts in the configured
directory:

```text
Use the anchore-mcp MCP server. Call anchore_policy_blocking_vulnerabilities
with image_registry="containers.example.com" and
image_repository="psf/help-site". Do not inspect or print env/config secrets.
Return compact JSON with policyRemediationStatus, selectedImage, and
blockingVulnerabilityCount.
```

The tool returns only vulnerability records that are proven policy blockers.
It does not return broad vulnerability lists, raw policy payloads, or unrelated
SBOM data.
