# anchore-mcp

Local, read-only MCP server for Anchore Enterprise. It exposes image listing, vulnerability, SBOM, policy, image-detail, policy-blocker, and remediation-handoff capabilities through FastMCP 3.4.3 over stdio.

Each process talks to one HTTPS Anchore deployment. Configure multiple MCP entries to use multiple deployments.

## Requirements and setup

- Python 3.12
- [`uv`](https://docs.astral.sh/uv/)

```bash
uv sync --frozen --all-groups
uv run python scripts/check.py
```

For a quicker test loop:

```bash
uv run pytest -q
```

## Configuration

The server recognizes exactly these seven environment variables; see [env.example](env.example):

| Variable | Required | Description |
|---|---:|---|
| `ANCHORE_URL` | Yes for real calls | HTTPS Anchore API base, such as `https://anchore.example` |
| `ANCHORE_TOKEN` | Yes for real calls | Basic-auth password; username is the literal `_api_key` |
| `ANCHORE_ACCOUNT` | No | Optional `x-anchore-account` value |
| `ANCHORE_API_VERSION` | No | `v2` by default; `v1` for a compatible legacy deployment |
| `ANCHORE_HTTP_MAX_RETRIES` | No | Additional idempotent-GET attempts, default `2` |
| `ANCHORE_HTTP_RETRY_BASE_MS` | No | Exponential-backoff base, default `300` ms |
| `ANCHORE_HTTP_RETRY_MAX_MS` | No | Backoff cap, default `8000` ms |

Retries apply only to transient 429 and 502–504 responses, `ConnectError`, and `ConnectTimeout`. Read, write, pool, and other request timeouts are not retried. Requests are bounded, redirects are disabled, and configuration is loaded at tool-call time. The MCP handshake and tool discovery therefore work without credentials; `anchore_connection_info` reports an unconfigured state normally.

Never commit credentials or print raw MCP environment configuration. Prefer the [protected launcher pattern](examples/codex-agent-setup/README.md).

## Run

```bash
uv run --frozen anchore-mcp
```

The process speaks MCP JSON-RPC over stdin/stdout only. It does not expose HTTP, SSE, or a listening port. Keep stdin open for the session; EOF causes a clean exit.

## MCP configuration

Use a local command entry, not a URL-and-headers entry. An example Codex configuration is:

```toml
[mcp_servers.anchore-mcp]
command = "/absolute/path/to/uv"
args = ["run", "--frozen", "anchore-mcp"]
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

All eight registrations carry advisory MCP annotations: `readOnlyHint=true`, `idempotentHint=true`, `destructiveHint=false`, and `openWorldHint=true`. Host-side allowlists and approval policy remain authoritative; audit new tools before enabling them.

Cursor users should select a command/stdio server, use the same `uv` command and arguments, and keep credentials in a protected launcher environment rather than inline JSON. The MCP child does not necessarily inherit an interactive shell profile.

## Native typed inputs

Digest-keyed tools accept a discriminated `locator` object:

```json
{"locator":{"kind":"digest","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
```

or an exact registry-qualified tagged reference:

```json
{"locator":{"kind":"reference","reference":"registry.example/team/app:1.0"}}
```

`anchore_policy_blocking_vulnerabilities` additionally accepts a repository locator:

```json
{"locator":{"kind":"repository","registry":"registry.example","repository":"team/app"}}
```

Short references such as `app:1.0` are rejected. Reference resolution uses `GET /v2/images?full_tag=...` (`fulltag` in v1) as a narrowing hint and trusts only exact bounded row evidence. Incomplete enumeration fails closed instead of becoming `no_match`. Repository selection uses the verified v2 image-tag summary route; legacy v1 requires bounded same-origin OpenAPI capability proof.

Policy `tag` and `base_digest` inputs are separate optional `/check` context and are never inferred from an arbitrary caller string.

## Results and evidence safety

Successful tools return concise text plus native structured content. Structured results include non-secret deployment context, warnings, selection/enumeration state where relevant, exact byte sizes, and the capability payload. Free-form text is PII-masked; raw structured Anchore evidence is intentionally unmasked for machine use and must be handled as sensitive data. Raw evidence is never copied wholesale to stderr.

The remediation handoff uses schema version `2.0.0`; see [the handoff contract](docs/remediation-handoff-schema.md). It is Anchore evidence, not remediation instruction.

## API route notes

- Default v2 images: `GET /v2/images`
- Vulnerabilities: `GET /v2/images/{digest}/vuln/all`
- Image SBOM: `GET /v2/images/{digest}/sboms/{native-json|spdx-json|cyclonedx-json}` — `sboms` is plural
- Policy: `GET /v2/images/{digest}/check`
- Detail: `GET /v2/images/{digest}`
- Repository summaries: `GET /v2/summaries/image-tags`

List responses may use `items`, `images`, or a top-level array depending on version. Pagination, total bytes, evidence traversal, candidates, OpenAPI documents, and response bodies are capped. The configured deployment’s version-matched `/v1/openapi.json` or `/v2/openapi.json` is authoritative for deployment-specific list parameters; OpenAPI is fetched from the same origin without redirects.

See [Anchore API research notes](docs/research/anchore-api-notes.md) for details.

## Troubleshooting

- Discovery works but calls fail: set `ANCHORE_URL` and `ANCHORE_TOKEN` in the MCP child environment, not only your terminal.
- URL rejected: only HTTPS URLs without embedded credentials, query, or fragment are accepted.
- Wrong or non-JSON route response: confirm `ANCHORE_API_VERSION`; Enterprise 5+ normally uses v2.
- Host drops the process: ensure stdin remains open and no wrapper writes a preamble to stdout.
- Reference cannot be proven: use a fully qualified tagged reference or digest and inspect the explicit enumeration/selection outcome.

## Development

The canonical local quality gate is:

```bash
uv run python scripts/check.py
```

Focused checks remain available through `uv run pytest`, `uv run ruff`, and `uv run pyright`. The package is Python 4.0.0, managed by `uv`, and tested against the locked FastMCP 3.4.3 contract.

Working notes live in [MEMORY.md](MEMORY.md); durable verified learnings live under [docs/solutions](docs/solutions). See [AGENTS.md](AGENTS.md#knowledge-flow) for the promotion flow.
