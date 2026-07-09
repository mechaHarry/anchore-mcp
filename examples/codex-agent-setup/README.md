# Protected Codex setup

This pattern exposes one local anchore-mcp process to one trusted repository without placing credentials inline in Codex configuration or source control.

## Private files

Create these files inside the consuming repository and ignore the entire directory:

```text
.codex/
  config.toml
  anchore-mcp.env
  anchore-mcp-launcher.sh
```

```gitignore
.codex/
```

Create them under a restrictive umask:

```bash
umask 077
mkdir -p .codex
```

## Configuration

`.codex/config.toml` contains no credentials:

```toml
[mcp_servers.anchore-mcp]
command = "/absolute/path/to/your-repo/.codex/anchore-mcp-launcher.sh"
args = []
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
```

The explicit allowlist is fail closed. Audit a future tool before enabling it. MCP read-only annotations are advisory and do not replace host approval policy.

## Environment file

`.codex/anchore-mcp.env` may contain exactly the seven supported variables. Replace the synthetic token locally and delete optional lines you do not need:

```bash
ANCHORE_URL=https://anchore.example
ANCHORE_TOKEN=synthetic-replace-me
ANCHORE_ACCOUNT=example-account
ANCHORE_API_VERSION=v2
ANCHORE_HTTP_MAX_RETRIES=2
ANCHORE_HTTP_RETRY_BASE_MS=300
ANCHORE_HTTP_RETRY_MAX_MS=8000
```

Never commit or print this file.

## Launcher

`.codex/anchore-mcp-launcher.sh`:

```sh
#!/bin/sh
set -eu
set -a
. "/absolute/path/to/your-repo/.codex/anchore-mcp.env"
set +a
exec "/absolute/path/to/uv" run --frozen --project "/absolute/path/to/anchore-mcp" anchore-mcp
```

Then protect and verify the private files:

```bash
chmod 700 .codex/anchore-mcp-launcher.sh
chmod 600 .codex/config.toml .codex/anchore-mcp.env
```

The launcher must not write a banner to stdout because stdout is reserved for MCP JSON-RPC. It starts a stdio process only; no HTTP URL or headers belong in Codex configuration.

## Prepare and verify

In the anchore-mcp clone:

```bash
uv sync --frozen --all-groups
uv run python scripts/check.py
```

Verify only non-secret paths and metadata:

```bash
test -x /absolute/path/to/uv
test -x /absolute/path/to/your-repo/.codex/anchore-mcp-launcher.sh
test -d /absolute/path/to/anchore-mcp
codex mcp get anchore-mcp --json | jq '{name, enabled, transport: {type: .transport.type, command: .transport.command, args: .transport.args, cwd: .transport.cwd}, enabled_tools}'
```

Do not print the raw MCP configuration; host diagnostics can expose inline environment values.

## Native prompt example

```text
Use anchore-mcp. Call anchore_policy_blocking_vulnerabilities with locator
{"kind":"repository","registry":"registry.example","repository":"team/app"}.
Return only the selected image, selection state, outcome, and blocker count.
Do not inspect or print MCP configuration or environment values.
```

The tool fails closed if it cannot prove the newest exact image. It returns only vulnerabilities proven to join to blocking policy findings, not a broad vulnerability list or raw policy payload.
