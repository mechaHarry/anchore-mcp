# Protected Codex setup

This pattern exposes one local anchore-mcp process to one trusted repository without placing credentials inline in Codex configuration or source control.

## Private files

Create these files inside the consuming repository and ignore the entire directory:

```text
.codex/
  config.toml
  anchore-mcp.env.json
  anchore-mcp-launcher.py
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
command = "/absolute/path/to/python3"
args = ["/absolute/path/to/your-repo/.codex/anchore-mcp-launcher.py"]
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

`.codex/anchore-mcp.env.json` is a data-only JSON object. It may contain exactly the seven supported variables. Replace the synthetic token locally and delete optional keys you do not need:

```json
{
  "ANCHORE_URL": "https://anchore.example",
  "ANCHORE_TOKEN": "synthetic-replace-me",
  "ANCHORE_ACCOUNT": "example-account",
  "ANCHORE_API_VERSION": "v2",
  "ANCHORE_HTTP_MAX_RETRIES": "2",
  "ANCHORE_HTTP_RETRY_BASE_MS": "300",
  "ANCHORE_HTTP_RETRY_MAX_MS": "8000"
}
```

Never commit or print this file.

## Launcher

`.codex/anchore-mcp-launcher.py` parses the environment file as JSON data, validates its keys and string values, removes inherited `ANCHORE_*` variables, and then replaces itself with the stdio server. Secret and account contents are never evaluated as shell syntax or printed:

```python
#!/usr/bin/env python3
import json
import os

ENV_PATH = "/absolute/path/to/your-repo/.codex/anchore-mcp.env.json"
UV_PATH = "/absolute/path/to/uv"
PROJECT_PATH = "/absolute/path/to/anchore-mcp"
ALLOWED = {
    "ANCHORE_URL",
    "ANCHORE_TOKEN",
    "ANCHORE_ACCOUNT",
    "ANCHORE_API_VERSION",
    "ANCHORE_HTTP_MAX_RETRIES",
    "ANCHORE_HTTP_RETRY_BASE_MS",
    "ANCHORE_HTTP_RETRY_MAX_MS",
}

try:
    with open(ENV_PATH, encoding="utf-8") as stream:
        values = json.load(stream)
    if not isinstance(values, dict):
        raise ValueError
    if not set(values) <= ALLOWED or not {"ANCHORE_URL", "ANCHORE_TOKEN"} <= set(values):
        raise ValueError
    if any(not isinstance(key, str) or not isinstance(value, str) for key, value in values.items()):
        raise ValueError
except (OSError, json.JSONDecodeError, TypeError, ValueError):
    raise SystemExit("anchore-mcp launcher configuration is invalid") from None

environment = {key: value for key, value in os.environ.items() if not key.startswith("ANCHORE_")}
environment.update(values)
arguments = [UV_PATH, "run", "--frozen", "--project", PROJECT_PATH, "anchore-mcp"]
os.execve(UV_PATH, arguments, environment)
```

Then protect and verify the private files:

```bash
chmod 600 .codex/config.toml .codex/anchore-mcp.env.json .codex/anchore-mcp-launcher.py
```

Configuration parsing reports only a fixed error and never echoes a key or value. The launcher must not write a banner to stdout because stdout is reserved for MCP JSON-RPC. It starts a stdio process only; no HTTP URL or headers belong in Codex configuration.

## Prepare and verify

In the anchore-mcp clone:

```bash
uv sync --frozen --all-groups
uv run python scripts/check.py
```

Verify only non-secret paths and metadata:

```bash
test -x /absolute/path/to/uv
test -x /absolute/path/to/python3
test -f /absolute/path/to/your-repo/.codex/anchore-mcp-launcher.py
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
