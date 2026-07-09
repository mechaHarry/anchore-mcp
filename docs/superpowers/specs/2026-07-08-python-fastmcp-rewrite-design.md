---
date: 2026-07-08
topic: python-fastmcp-rewrite
status: approved
release: 4.0.0
---

# Python and FastMCP Rewrite Design

## Summary

Rewrite `anchore-mcp` as a Python 3.12 application managed by `uv` and built on FastMCP 3.x. The release is a clean architectural break: it preserves the current eight Anchore capabilities and their trust guarantees, but it does not preserve the TypeScript wire contract. It adopts FastMCP-native typed inputs, structured output, tool annotations, lifespan management, and in-memory protocol testing.

The server remains a local stdio MCP. It is launched with `uv run anchore-mcp`, connects to exactly one Anchore Enterprise deployment per process, and reads the existing `ANCHORE_*` environment variables. The rewrite is released as `4.0.0`.

## Decisions

- Use Python 3.12 and an exact FastMCP 3.x pin. The design-date version is `fastmcp==3.4.3`; `uv.lock` locks the complete dependency graph.
- Keep stdio as the only transport.
- Preserve the current eight user capabilities and tool names, but use new Python-native input and output contracts.
- Make a clean break with no deprecated aliases or legacy result wrapper.
- Put thin FastMCP adapters over a typed, framework-independent domain core.
- Use a lifespan-managed shared `httpx.AsyncClient` for Anchore requests.
- Implement retries at the Anchore HTTP request layer, not with FastMCP whole-tool retry middleware.
- Keep connection configuration lazy so startup and MCP discovery work without Anchore credentials.
- Develop beside the TypeScript implementation, cut over only after capability and trust-boundary verification, then remove Node and TypeScript.

## Goals

- Preserve AI access to connection context, image listing, vulnerabilities, SBOMs, policy checks, policy-blocking vulnerabilities, image detail, and remediation handoff.
- Improve machine usability with typed schemas and structured MCP results.
- Improve latency with async I/O, connection reuse, HTTP/2 negotiation, and bounded parallelism.
- Improve resource safety by bounding response bodies, enumeration, caches, connections, and owned tasks.
- Preserve or strengthen fail-closed image selection and policy correlation.
- Preserve graceful, Anchore-aware backoff for transient GET failures.
- Make every capability and trust boundary independently testable.

## Non-goals

- No Streamable HTTP, SSE, remote service mode, or inbound authentication.
- No Anchore write operations, image uploads, scan triggers, remediation execution, rebuilds, or CI/CD orchestration.
- No new named export capabilities in this release.
- No generated tool surface from Anchore OpenAPI.
- No preservation of the TypeScript JSON-in-text wrapper, flat locator parameters, or legacy error envelope.
- No FastMCP response cache, background task worker, generic retry middleware, or automatic whole-tool retries.

## Package Architecture

The package uses a `src` layout under `src/anchore_mcp/`:

| Area | Responsibility |
|---|---|
| `__main__.py` | Minimal executable entrypoint; starts the stdio server. |
| `server.py` | Creates FastMCP, declares server metadata, and registers eight tools. |
| `runtime.py` | FastMCP lifespan, shared HTTP client, connection limits, bounded caches, and deterministic shutdown. |
| `config.py` | Lazy environment parsing and secret-aware connection models. |
| `models/` | Pydantic request, result, context, evidence, and enumeration models. |
| `anchore/routes.py` | Version-specific v1 and v2 REST paths and query keys. |
| `anchore/http.py` | Authenticated GET requests, streaming size enforcement, JSON parsing, and safe error mapping. |
| `anchore/retry.py` | Explicit transient classification, retry budget, `Retry-After`, exponential backoff, and jitter. |
| `anchore/pagination.py` | Same-origin bounded page traversal and completeness reporting. |
| `anchore/openapi.py` | Same-origin, no-redirect, size-bounded OpenAPI retrieval and one-entry expiring cache. |
| `domain/images.py` | Bounded image evidence extraction and exact-reference resolution. |
| `domain/selection.py` | Fail-closed newest-image selection for policy reporting. |
| `domain/vulnerabilities.py` | Vulnerability normalization and exact blocker correlation. |
| `domain/policy.py` | Policy state and blocking-finding interpretation. |
| `domain/handoff.py` | Concurrent evidence assembly for remediation handoff. |
| `tools/` | Thin FastMCP tool adapters; no HTTP or evidence parsing logic. |
| `security/pii.py` | Textual PII detection, masking, and warnings. |
| `security/logging.py` | Bounded redacted stderr logging. |

Domain modules do not import FastMCP. Tool adapters translate Pydantic inputs into domain calls and domain results into FastMCP `ToolResult` values. This boundary permits direct unit testing without an MCP runtime.

## Runtime and Configuration

`uv run anchore-mcp` inherits its process environment. Existing host configurations continue to provide:

- `ANCHORE_URL` — required for real calls; HTTPS only; normalized without trailing slashes.
- `ANCHORE_TOKEN` — required for real calls; Basic authentication password with the literal username `_api_key`.
- `ANCHORE_ACCOUNT` — optional `x-anchore-account` value.
- `ANCHORE_API_VERSION` — optional `v1` or `v2`; defaults to `v2`.
- `ANCHORE_HTTP_MAX_RETRIES` — optional retry count override.
- `ANCHORE_HTTP_RETRY_BASE_MS` — optional exponential-backoff base.
- `ANCHORE_HTTP_RETRY_MAX_MS` — optional delay cap.

No configuration object validates Anchore credentials at module import or server construction. Each tool invocation loads and validates a connection snapshot. `anchore_connection_info` converts missing configuration into a normal structured result; other tools return a safe FastMCP tool error. This keeps trust probes and tool discovery credential-free.

The lifespan creates an unconfigured shared `httpx.AsyncClient`. Authentication and account headers are applied per request from the invocation's connection snapshot. Shutdown closes the client, cancels owned tasks, waits for cancellation completion, and clears the OpenAPI cache.

## FastMCP Tool Design

The server retains these eight names:

1. `anchore_connection_info`
2. `anchore_list_images`
3. `anchore_image_vulnerabilities`
4. `anchore_image_sbom`
5. `anchore_image_policy_check`
6. `anchore_policy_blocking_vulnerabilities`
7. `anchore_image_detail`
8. `anchore_remediation_handoff`

Every tool has these annotations:

- `readOnlyHint=true`
- `idempotentHint=true`
- `destructiveHint=false`
- `openWorldHint=true`

Annotations are advisory metadata, not security controls.

### Locator inputs

Digest-keyed tools accept a Pydantic discriminated union named `locator`:

- `{ "kind": "digest", "digest": "sha256:..." }`
- `{ "kind": "reference", "reference": "registry/repository:tag" }`

`anchore_policy_blocking_vulnerabilities` additionally accepts:

- `{ "kind": "repository", "registry": "registry.example", "repository": "team/image" }`

The discriminator makes mutually exclusive states unrepresentable in a valid request. Policy-check and remediation tools retain distinct optional `tag` and `base_digest` inputs because those values are policy context, not image locators. Remediation handoff retains `include_policy_check`, defaulting to true. SBOM format remains the enum `normal`, `spdx`, or `cyclonedx`.

### Results

Tools return `ToolResult` with both:

- concise text content for an LLM or human; and
- typed `structuredContent` for programmatic consumers.

All successful structured results include:

- non-secret deployment context: base URL, optional account, API version, and action;
- a typed capability-specific result;
- payload byte counts where responses may be large;
- explicit warnings;
- explicit completeness state for bounded enumeration.

Raw Anchore evidence remains unmasked structured data for fidelity. Generated text is PII-masked and accompanied by an explicit warning when a heuristic matches. Raw evidence is never copied into operational logs.

Expected failures use sanitized FastMCP tool errors. They do not expose tokens, headers, response bodies, environment dumps, tracebacks, or internal exception strings. The new native structured contract replaces the old JSON-in-text error envelope.

The remediation handoff schema is breaking and advances to `handoffVersion: "2.0.0"`. It retains deployment, selected image digest, generation time, evidence, per-response sizes, and optional policy evidence. The documentation in `docs/remediation-handoff-schema.md` is updated during cutover.

## Data Flow

For each call:

1. FastMCP and Pydantic validate input.
2. The adapter loads a current environment connection snapshot.
3. A domain service resolves the locator if required.
4. The Anchore HTTP layer performs one or more authenticated, bounded GET requests.
5. The domain layer validates evidence and builds a typed result.
6. The adapter returns concise masked text and structured content.

Policy-blocking vulnerability evaluation preserves trust-sensitive sequencing: evaluate policy first, return immediately when already green, and fetch vulnerability evidence only when policy evidence requires correlation. Correlation remains exact by vulnerability identifier or exact package identity; the server never substitutes a broad high-severity list.

Remediation handoff fetches independent detail and vulnerability evidence concurrently, plus policy evidence when requested. Structured concurrency cancels sibling requests on failure and propagates client cancellation. No detached background work survives a tool call.

## Anchore HTTP and Backoff

FastMCP `RetryMiddleware` is intentionally disabled. It wraps a complete MCP tool call and could repeat successful requests in a multi-request tool. The Anchore request layer instead retries only the individual idempotent GET that failed.

Retry behavior:

- Retry connection failures and HTTP `429`, `502`, `503`, and `504` while attempts remain.
- Use exponential backoff with full jitter.
- Honor bounded `Retry-After` in integer-seconds or HTTP-date form.
- Make sleeps cancellation-aware.
- Do not retry authentication or authorization failures, invalid input, oversized responses, invalid JSON, policy-trust failures, or other permanent HTTP statuses.
- Do not automatically retry a read timeout after response transfer has begun.
- Apply a finite per-request retry budget using the existing environment controls and safe defaults.

The HTTP client uses a bounded connection pool with keepalive reuse, HTTP/2 when negotiated, and HTTP/1.1 fallback. Initial defaults are 20 total connections, 10 keepalive connections, and 30 seconds of keepalive expiry. Request phase defaults are 10 seconds for connect, pool, and write and 60 seconds for read. Handoff parallelism is capped at three requests. These are internal constants in 4.0.0 rather than new public configuration. All Anchore I/O is asynchronous.

## Bounded Data and SSRF Controls

- Stream decoded response bytes and enforce the configured expanded-size bound before JSON parsing. This protects against large and compressed payload expansion.
- Disable redirects for credentialed Anchore and OpenAPI requests.
- Accept pagination links only when scheme, host, and effective port match the configured Anchore origin.
- Percent-encode path identifiers and construct query parameters with `httpx` parameter APIs.
- Preserve explicit maximum pages, items, evidence entries, evidence string lengths, disambiguation candidates, query keys, and query value lengths.
- Treat a cap or evidence overflow as incomplete enumeration, never as no match.
- Keep a single version-matched OpenAPI cache entry with monotonic expiry; replacement cannot grow process memory.
- Reject non-JSON responses safely without including their bodies in errors.

The implementation starts with the current proven bounds unless a test-backed change demonstrates a safer and more useful value.

## Image and Policy Trust Rules

- v2 exact reference lookup uses `GET /v2/images?full_tag=...`; v1 uses `fulltag`.
- A backend filter is only a narrowing hint. A row must contain bounded exact-reference evidence before its digest is trusted.
- Shared exact-reference resolution uses digest cardinality and does not infer newest by timestamp.
- Multiple proven digests require disambiguation; incomplete evidence or page traversal fails closed.
- Repository selection for policy reporting uses the verified v2 image-tag summary route.
- Legacy v1 repository selection remains disabled unless same-origin, no-redirect, bounded OpenAPI evidence explicitly advertises direct registry and repository filters.
- Newest selection is limited to the policy-blocking capability and requires a trusted analysis timestamp for every matching digest-bearing candidate. Missing timestamps and tied newest digests fail closed.
- v2 vulnerability and SBOM paths retain `/vuln/all` and plural `/sboms/{format}` semantics.

## Logging and PII

Stdout is reserved exclusively for MCP JSON-RPC. Python logging is configured for stderr and FastMCP payload logging is disabled.

Operational log lines are redacted before truncation. Redaction covers Basic and Bearer credentials, authorization headers, token-like query keys, and configured secrets. Lines are capped, raw Anchore response bodies are never logged, and tracebacks are not sent to clients.

Generated prose detects and masks the currently supported email, US-SSN-like, and North-American-phone-like patterns. A deduplicated warning explains that masking is heuristic and distribution still requires care. Structured Anchore evidence remains unmasked as required for security investigation and is not persisted by the server.

## Performance and Resource Lifecycle

- Reuse one async HTTP connection pool for the process lifetime.
- Negotiate HTTP/2 with HTTP/1.1 fallback.
- Limit pool connections, keepalive connections, and concurrent evidence requests.
- Parallelize only independent handoff requests; keep trust-dependent policy flow sequential.
- Avoid blocking network and file operations in the event loop.
- Use bounded buffers rather than unbounded response reads.
- Propagate cancellation through HTTP requests and retry sleeps.
- Close the pool and await owned-task termination during lifespan shutdown.

Performance tests measure startup, MCP discovery, connection reuse, concurrent handoff latency, and bounded memory growth. Performance changes must not weaken trust or response-size controls.

## Testing Strategy

Every behavior is introduced test-first. Test categories are:

- Unit tests for routes, retries, bounds, evidence extraction, reference resolution, selection, policy joins, PII, and error sanitization.
- `respx` HTTP tests for authentication, account headers, v1/v2 paths, pagination, redirect rejection, streaming limits, compressed expansion, retries, `Retry-After`, timeouts, and cancellation.
- FastMCP in-memory client tests for all eight tools, Pydantic schemas, annotations, structured results, and safe errors.
- Real stdio subprocess tests for credential-free startup, discovery, stdout purity, invocation, cancellation, and shutdown.
- Property-based tests for adversarial references, malformed pagination, oversized evidence, and hostile Anchore JSON shapes.
- Lifecycle tests that repeat startup and shutdown and assert no surviving owned tasks, connections, or cache entries.
- Focused performance tests with regression tolerances rather than vanity benchmarks.
- Optional live Anchore smoke tests, disabled by default, that never log secrets, raw customer data, or non-public identifiers.

Semantic comparison tests use representative TypeScript fixtures to preserve capabilities and trust outcomes. They do not require legacy MCP schemas or text wrappers to match.

## Tooling and Quality Gate

The repository gains `pyproject.toml`, `uv.lock`, a console script named `anchore-mcp`, and development dependencies for pytest, pytest-asyncio, pytest-cov, Hypothesis, respx, Ruff, Pyright, `build`, and `pip-audit`.

The canonical local and CI gate is `uv run python scripts/check.py`. That checked-in orchestrator runs commands without a shell and stops at the first failure:

1. `ruff format --check .`
2. `ruff check .`
3. `pyright`
4. `python -m build`
5. `pip-audit`
6. `pytest`

The project quality gate checks:

1. formatting;
2. Ruff linting;
3. strict type checking;
4. package build and metadata;
5. dependency vulnerabilities;
6. the complete pytest suite with line and branch coverage configured to fail below 90 percent overall.

CI runs from the committed lock with `uv sync --frozen`. Coverage is used to find untested risk, not to reward empty assertions; security, selection, bounds, and error paths require direct behavioral tests.

## Migration and Cutover

1. Add the Python package and quality tooling without changing the active Node launcher.
2. Port HTTP, retry, route, pagination, OpenAPI, security, and domain logic test-first.
3. Add the eight native FastMCP tools and protocol tests.
4. Run semantic comparison tests and the complete Python quality gate.
5. Update README, AGENTS guidance, environment examples, host configurations, CI, and remediation handoff documentation.
6. Switch the supported launcher to `uv run anchore-mcp` and run real stdio smoke tests.
7. Verify startup latency, request reuse, cancellation, memory bounds, and clean shutdown.
8. Remove Node, pnpm, TypeScript, compiled-output assumptions, and legacy tests.
9. Release `4.0.0`.

The current uncommitted `package.json` and `pnpm-workspace.yaml` changes are user-owned. The design commit does not modify them. Before the removal step, their intent must be reconciled explicitly so the migration does not silently discard unrelated work.

## Documentation Changes

- Rewrite setup and host examples around `uv sync --frozen` and `uv run anchore-mcp`.
- Preserve the one-deployment-per-process model and existing environment variable documentation.
- Document typed locator objects and structured outputs with examples.
- Document read-only annotations as advisory rather than enforcement.
- Update the remediation handoff contract to version 2.0.0.
- Replace stdout/stderr Node guidance with equivalent Python logging invariants.
- Record stable FastMCP, httpx, retry, and resource-lifecycle learnings under `docs/solutions/` after they are verified in implementation.

## Acceptance Criteria

- `uv run anchore-mcp` starts a stdio MCP and completes discovery without Anchore credentials.
- The server exposes exactly the eight named capabilities with read-only annotations and typed schemas.
- The existing `ANCHORE_*` environment variables configure real Anchore calls without repository-stored secrets.
- All eight capabilities preserve current Anchore reach, fail-closed selection, bounded enumeration, and remediation evidence semantics.
- Results provide concise masked text and typed structured content.
- Retry behavior is request-scoped, bounded, cancellation-aware, and honors transient Anchore responses.
- Response bodies, enumeration, caches, connections, and task lifetimes are bounded and tested.
- Operational logs cannot contain configured tokens, authorization headers, or full Anchore payloads.
- Repeated startup, use, cancellation, and shutdown show no owned resource leak.
- The complete Python quality gate and stdio smoke suite pass before TypeScript removal.
- Node and TypeScript are absent from the final 4.0.0 runtime and development workflow.

## References

- [Anchore Enterprise MCP requirements](../../brainstorms/2026-04-02-anchore-enterprise-mcp-requirements.md)
- [Anchore API notes](../../research/anchore-api-notes.md)
- [Current remediation handoff schema](../../remediation-handoff-schema.md)
- [Anchore v2 image lookup routes](../../solutions/integration-issues/2026-07-08-anchore-v2-image-lookup-routes.md)
- [FastMCP installation and versioning](https://gofastmcp.com/getting-started/installation)
- [FastMCP tools and annotations](https://gofastmcp.com/servers/tools)
- [FastMCP middleware](https://gofastmcp.com/servers/middleware)
- [FastMCP lifespan](https://gofastmcp.com/servers/lifespan)
- [FastMCP server execution and stdio](https://gofastmcp.com/deployment/running-server)
