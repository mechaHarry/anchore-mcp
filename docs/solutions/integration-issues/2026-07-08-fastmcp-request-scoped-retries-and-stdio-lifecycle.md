---
module: anchore-mcp
date: 2026-07-08
problem_type: integration_issue
component: tooling
severity: high
symptoms:
  - MCP discovery fails when Anchore credentials are absent
  - Retry or response state leaks between concurrent tool calls
  - Stdio probes hang or leave subprocesses and sockets alive after EOF or cancellation
  - Backend evidence appears in stdout or unbounded stderr diagnostics
root_cause: lifecycle_mismatch
resolution_type: architecture_fix
tags:
  - fastmcp
  - httpx
  - stdio
  - retries
  - cancellation
  - resource-lifecycle
---

# Keep Anchore retries request-scoped and runtime resources lifespan-owned

## Context

FastMCP hosts may discover tools before workspace trust or credentials are available, reuse one server session for multiple calls, cancel requests, or close stdin as a short-lived probe. Anchore calls need connection reuse and graceful backoff without allowing one request’s retry, response, or cancellation state to affect another.

## Wrong behavior and symptoms

- Reading `ANCHORE_URL` and `ANCHORE_TOKEN` during module import or server construction prevents credential-free MCP discovery.
- Creating a new HTTP client in every adapter wastes connections, while keeping response or retry counters on a shared client lets concurrent calls interfere.
- Framework retry middleware can retry non-Anchore operations or compound the application’s bounded retry policy.
- Treating stdin EOF as an exceptional crash creates noisy probes; ignoring cancellation leaves subprocesses, tasks, response streams, or sockets alive.
- Logging complete validation input, JSON-RPC payloads, or Anchore bodies can expose tokens, PII, and raw evidence.

## Root cause

Process, MCP-session, and request lifetimes were conflated. Configuration is request-time state; the connection pool and OpenAPI cache are session resources; attempts, streamed responses, and backoff sleeps belong to one Anchore request. Stdio itself is the process transport and must remain protocol-clean.

## Resolution

1. Construct FastMCP without reading Anchore configuration. Register the exact tools and allow discovery to complete without credentials.
2. Create one bounded `httpx.AsyncClient` in the FastMCP lifespan. Share it through the request context and close it in lifespan teardown.
3. Load and validate the seven supported `ANCHORE_*` variables inside tool execution. Keep tokens in `SecretStr` and authorization headers only.
4. Implement retry inside the Anchore GET operation. Keep attempt count and backoff sleep local to that call; retry only `ConnectError`, `ConnectTimeout`, and 429/502–504. Do not retry read, write, pool, or other request timeouts.
5. Stream each response under an explicit byte ceiling, close it on every success, failure, oversize, or cancellation path, and disable redirects.
6. Keep pagination, aggregate bytes, OpenAPI structures, evidence traversal, candidate lists, and caches independently bounded. Fail closed when proof is incomplete.
7. Run FastMCP over stdio only. stdout contains JSON-RPC only; bounded stderr contains sanitized operational events, never payloads or evidence.
8. On request cancellation, propagate cancellation, close the active response stream, and cancel only request-owned work; keep the shared client available for the session. On lifespan teardown or stdio EOF, close owned tasks, cache state, the HTTP client, and the subprocess.

FastMCP’s read-only/idempotent annotations describe intent but do not enforce authorization. Host approvals and the exact enabled-tool allowlist remain necessary.

## Verification

- In-memory discovery proves the exact eight-tool contract and annotations without credentials.
- Real stdio tests prove discovery has no stdout preamble, EOF exits within two seconds, and cancellation leaves no transport task or child process.
- Lifecycle tests enter and exit the runtime 25 times, then assert the client is closed, OpenAPI cache size is zero, owned tasks are empty, and no named task survives.
- Event-based tests prove independent handoff evidence requests overlap while policy-blocker vulnerability retrieval begins only after policy evidence requires it.
- HTTP tests cover retry status classification, exponential bounds, cancellation during backoff and streaming, response byte caps, and connection reuse.
- Deterministic property tests exercise hostile references, continuation links, and nested JSON shapes against fixed cardinality and traversal caps.

Run:

```bash
uv run python scripts/check.py
uv run pytest tests/mcp/test_stdio.py tests/runtime tests/property -q
```

## Related

- [Anchore API research notes](../../research/anchore-api-notes.md)
- [Python FastMCP rewrite design](../../superpowers/specs/2026-07-08-python-fastmcp-rewrite-design.md)
- [Remediation handoff 2.0.0](../../remediation-handoff-schema.md)
