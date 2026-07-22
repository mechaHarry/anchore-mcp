# anchore-mcp

Read-only MCP server for Anchore Enterprise. It runs locally over **stdio** and exposes eight image, vulnerability, SBOM, policy, detail, and remediation-evidence tools to Codex.

## Install and run

Prerequisites: Python 3.12 and [`uv`](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/mechaHarry/anchore-mcp.git
cd anchore-mcp
uv sync --frozen
uv run --frozen anchore-mcp
```

The last command starts the stdio server and waits for an MCP host. For normal use, configure Codex instead of running it in a separate terminal.

## Environment

The server recognizes exactly these seven variables:

| Variable | Required | Default / meaning |
|---|---:|---|
| `ANCHORE_URL` | Yes | HTTPS Anchore API base |
| `ANCHORE_TOKEN` | Yes | API token; Basic-auth username is the literal `_api_key` |
| `ANCHORE_ACCOUNT` | No | Optional `x-anchore-account` value |
| `ANCHORE_API_VERSION` | No | `v2`; use `v1` only for a compatible legacy deployment |
| `ANCHORE_HTTP_MAX_RETRIES` | No | `2` additional attempts |
| `ANCHORE_HTTP_RETRY_BASE_MS` | No | `300` ms exponential-backoff base |
| `ANCHORE_HTTP_RETRY_MAX_MS` | No | `8000` ms backoff cap |

Retries apply only to idempotent GET `ConnectError`, `ConnectTimeout`, and HTTP 429/502/503/504 failures. Read, write, pool, and other request timeouts are not retried.

## Minimal Codex configuration

Add this to your Codex `config.toml`, replacing only the absolute executable and repository paths and the synthetic environment values:

```toml
[mcp_servers.anchore-mcp]
command = "/absolute/path/to/uv"
args = ["run", "--frozen", "--project", "/absolute/path/to/anchore-mcp", "anchore-mcp"]
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

[mcp_servers.anchore-mcp.env]
ANCHORE_URL = "https://anchore.example"
ANCHORE_TOKEN = "synthetic-replace-me"
ANCHORE_ACCOUNT = "synthetic-account"
ANCHORE_API_VERSION = "v2"
ANCHORE_HTTP_MAX_RETRIES = "2"
ANCHORE_HTTP_RETRY_BASE_MS = "300"
ANCHORE_HTTP_RETRY_MAX_MS = "8000"
```

Codex configuration inspection can display inline environment values. Keep the file out of source control, restrict it to mode `0600`, and never paste its raw contents into diagnostics:

```bash
chmod 600 ~/.codex/config.toml
```

For credentials stored separately from Codex TOML, use the [protected JSON launcher setup](examples/codex-agent-setup/README.md).

## Verify

Restart Codex after changing its configuration, then use:

```text
Use the anchore-mcp MCP server. Call anchore_connection_info. Return only
whether it is configured and the API version. Do not print the URL, account,
MCP configuration, or environment values.
```

Image tools use a typed locator. For example, `anchore_image_detail` accepts:

```json
{
  "locator": {
    "kind": "digest",
    "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }
}
```

Replace the synthetic digest with an approved image digest before making a real call. Structured Anchore evidence is intentionally unmasked; request only the fields you need and handle the result as sensitive data.

## Troubleshooting

- **Missing configuration:** the MCP child needs `ANCHORE_URL` and `ANCHORE_TOKEN`; values exported only in an interactive terminal may not reach Codex.
- **HTTPS:** `ANCHORE_URL` must be HTTPS and must not contain embedded credentials, a query, or a fragment.
- **stdio:** configure a local command, not an HTTP/SSE URL; keep stdin open and do not use wrappers that print banners to stdout.
- **Policy blockers:** red vulnerability policies are correlated only to exact normalized vulnerability IDs or exact package identities. Rich but bounded Anchore vulnerability rows are supported; oversized, deeply nested, or structurally invalid evidence still fails closed.

See the [remediation handoff contract](docs/remediation-handoff-schema.md) and [Anchore API notes](docs/research/anchore-api-notes.md) for advanced integration details.
