# Agent guidance — anchore-mcp

Local Python 3.12, FastMCP 3.4.4 **stdio** server for read-only Anchore Enterprise evidence. One HTTPS deployment is configured per process; use separate MCP entries for separate deployments.

## Sources of truth

- Requirements: [docs/brainstorms/2026-04-02-anchore-enterprise-mcp-requirements.md](docs/brainstorms/2026-04-02-anchore-enterprise-mcp-requirements.md)
- Python design and plan: [design](docs/superpowers/specs/2026-07-08-python-fastmcp-rewrite-design.md), [plan](docs/superpowers/plans/2026-07-08-python-fastmcp-rewrite.md)
- API research: [docs/research/anchore-api-notes.md](docs/research/anchore-api-notes.md)
- Handoff 2.0.0: [docs/remediation-handoff-schema.md](docs/remediation-handoff-schema.md)
- Durable learnings: [docs/solutions](docs/solutions)

## Knowledge flow

[MEMORY.md](MEMORY.md) is a short-lived staging cache. Read it early for substantive work, but do not treat it as canonical. Promote verified, durable learnings into a Compound-style file under `docs/solutions/<category>/`, then remove or shorten the promoted MEMORY entry. Do not duplicate durable guidance in both layers.

## Architecture

| Area | Role |
|---|---|
| `src/anchore_mcp/__main__.py` | Minimal console entrypoint; imports `run()` without starting anything at package import time |
| `src/anchore_mcp/server.py` | FastMCP construction, lifespan, exact eight tool registrations, stdio run |
| `src/anchore_mcp/runtime.py` | Lifespan-owned `httpx.AsyncClient`, Anchore client, OpenAPI cache, task cleanup |
| `src/anchore_mcp/config.py` | Lazy environment parsing and HTTPS validation |
| `src/anchore_mcp/anchore/` | Bounded HTTP, retry, routes, pagination, and OpenAPI capability discovery |
| `src/anchore_mcp/domain/` | Framework-independent selection, policy, vulnerability, and handoff logic |
| `src/anchore_mcp/models/` | Pydantic locators and structured result contracts |
| `src/anchore_mcp/tools/` | Thin FastMCP adapters; raw evidence stays in structured content |
| `src/anchore_mcp/security/` | PII masking and bounded stderr logging |

The runtime is created by the FastMCP lifespan, shared across calls in one session, and always closed. Configuration remains lazy: missing credentials must not prevent discovery, trust prompts, or `anchore_connection_info`.

## Environment contract

Recognize exactly these seven variables:

| Variable | Meaning |
|---|---|
| `ANCHORE_URL` | Required for real calls; HTTPS only |
| `ANCHORE_TOKEN` | Required API token; Basic password with literal username `_api_key` |
| `ANCHORE_ACCOUNT` | Optional `x-anchore-account` |
| `ANCHORE_API_VERSION` | `v2` default or compatible legacy `v1` |
| `ANCHORE_HTTP_MAX_RETRIES` | Bounded extra attempts |
| `ANCHORE_HTTP_RETRY_BASE_MS` | Backoff base |
| `ANCHORE_HTTP_RETRY_MAX_MS` | Backoff cap |

Do not add secret files or log environment values. Use reserved synthetic domains and tokens in committed examples and tests.

## API and trust invariants

- Default routes are explicitly v2: `GET /v2/images`, `/v2/images/{digest}/vuln/all`, `/v2/images/{digest}/check`, `/v2/images/{digest}`, and `/v2/images/{digest}/sboms/{format}`. Image SBOM uses plural `sboms`.
- Exact reference resolution queries `/v2/images?full_tag=...` (`fulltag` for v1) but treats the filter only as narrowing. Accept a digest only from bounded exact row evidence.
- Repository selection for the policy-blocker tool uses `/v2/summaries/image-tags`. V1 requires same-origin, no-follow, bounded OpenAPI evidence advertising compatible direct filters.
- Never guess through incomplete enumeration, evidence overflow, ambiguous digests, missing trusted timestamps, or newest-image ties. Fail closed with explicit selection state or a safe error.
- List responses can use `items`, `images`, or a top-level array. Bound pages, items, total bytes, response bytes, JSON traversal, candidates, hints, and OpenAPI structures.
- The deployment’s version-matched `/v1/openapi.json` or `/v2/openapi.json` is authoritative for deployment-specific list parameters. Do not follow redirects or accept cross-origin capability evidence.
- Retry only idempotent GET `ConnectError`, `ConnectTimeout`, and transient 429/502–504 responses with bounded exponential backoff and jitter. Do not retry read, write, pool, or other request timeouts.
- Handoff 2.0.0 is evidence, not instruction. Detail, vulnerabilities, and optional policy fetches share one proven digest; any required failure fails the composite result.

## MCP and security invariants

- stdout is MCP JSON-RPC only. Never print banners, diagnostics, or evidence there.
- stderr is bounded operational output only. Never log credentials, authorization headers, locator payloads, validation input, or full Anchore bodies.
- Free-form text is PII-masked. Structured Anchore JSON is intentionally unmasked for machine use and must not be copied to stderr.
- All tools are advisory read-only/idempotent/non-destructive/open-world annotations. Annotations do not replace host approvals.
- Keep transport stdio-only. Do not add HTTP/SSE serving, payload logging, retry middleware, response cache middleware, or background tool tasks.
- Cancellation must propagate; cleanup must close sockets, clear cache state, and leave no owned tasks.
- Treat destructive behavior as Terraform-like: require explicit human approval.

## Inputs and results

Use discriminated locator objects (`kind: digest`, `reference`, or policy-only `repository`), not legacy flat locator fields. Keep Zod-era wrapper names out of new Python contracts. Successful tools return concise masked text and native structured content with context, warnings, enumeration/selection state, evidence, and observed byte sizes.

## Build and tests

```bash
uv sync --frozen --all-groups
uv run python scripts/check.py
```

Focused commands:

```bash
uv run pytest -q
uv run ruff format --check src tests
uv run ruff check src tests
uv run pyright src tests
uv build
```

Every feature and bug fix requires a strict test. Prefer semantic and in-memory MCP tests over legacy wrapper snapshots. Real stdio tests must verify credential-free discovery, clean EOF/cancellation, and no payload preamble. Synthetic servers bind only `127.0.0.1`, use reserved data, and never record authorization.

When routes or runtime behavior change, update API research and fossilize only verified learnings. Preserve simple designs, graceful backoff, PII paranoia, security review, memory/resource cleanup, and parallel UI/data concerns if a UI is ever added.
