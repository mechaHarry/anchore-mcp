---
date: 2026-04-03
topic: anchore-mcp-v2
focus: v2 roadmap aligned with human/todo.md (image filtering, tag-first SBOM UX, HTTP MCP, robust tests, API backoff)
---

# Ideation: anchore-mcp v2

## Codebase Context

**Project shape:** TypeScript stdio MCP server for Anchore Enterprise (`McpServer` + `StdioServerTransport`). Anchore access via `createAnchoreClient`, versioned paths in `src/anchore/api-paths.ts`, tools under `src/tools/`. Lazy `loadConnectionFromEnv()` at tool time; no global uncaught handlers in entry. R8/R13/R14: structured tool JSON with context, stderr discipline, PII masking on textual paths.

**Notable patterns:** Digest-centric v2 routes for SBOM/vuln/detail (`/v2/images/{digest}/sboms/...` plural `sboms`). List responses normalized for `items` vs `images`. Original implementation plan: stdio-only v1, mocked HTTP in CI, pagination deferred, timeout behavior documented as no retry.

**Obvious gaps vs human goals:** List filtering was limited to public `fulltag` (wire `full_tag`) and `vulnerability_id`; no generic API-level string filter. SBOM tool required `image_digest` only—no tag-first path. No HTTP/SSE MCP transport. Client: timeout, explicitly no retries on timeout. Tests were mock-heavy; limited contract drift detection.

**Past learnings (`docs/solutions/`, research):** v2 SBOM path uses `sboms`; wrong segment can 400. Digest vs tag: paths expect `sha256:…`; policy check may allow tag query params—does not replace digest for SBOM routes. `/v2/openapi.json` is deployment source of truth. Remediation handoff schema is the stable downstream contract.

**Issue intelligence:** Not used (ideation was codebase- and todo-driven, not issue-tracker-driven).

---

## Ranked Ideas

### 1. Server-aligned image list: filters and pagination

**Description:** Extend `anchore_list_images` (and helpers) so filters and paging follow each deployment’s `GET /v2/images` contract—e.g. substring/name/repo filters where OpenAPI documents them, plus cursor/limit when the API exposes continuation. Prefer OpenAPI-driven parameter names over ad-hoc client-only filtering.

**Rationale:** Addresses human/todo “proper api level filter images by string” and the deferred pagination note; reduces payload size and model noise for large inventories.

**Downsides:** Behavioral variance across Anchore builds; may need capability detection or clear errors when a filter is unsupported.

**Confidence:** 78%

**Complexity:** Medium

**Status:** Unexplored

---

### 2. Tag-first SBOM path (resolve to digest, then SBOM)

**Description:** Accept an image reference (repo:tag or digest) via a dedicated flow or optional parameters; resolve to canonical `sha256:…` using list/detail APIs, with structured disambiguation when multiple records match; then call existing SBOM routes. Optionally expose a single composite tool (e.g. SBOM for tag) that chains steps and returns resolved digest in tool context.

**Rationale:** Matches human/todo “Simpler UX… user is only ever concerned with image tags and names”; aligns with institutional digest-centric v2 APIs and `docs/solutions` guidance.

**Downsides:** Tag ambiguity and multi-arch require explicit UX; extra HTTP round-trips unless carefully bounded.

**Confidence:** 85%

**Complexity:** Medium

**Status:** Explored (brainstorm 2026-04-03 — see `docs/brainstorms/2026-04-03-image-reference-digest-resolution-requirements.md`)

---

### 3. Optional remote MCP: HTTP/SSE transport and configurable headers

**Description:** Keep stdio as the default entry; add an alternate binding (e.g. Streamable HTTP) that registers the same tools and schemas, with support for static or extra HTTP headers (gateways, tracing, org policies). Treat security explicitly: auth, TLS, rate limits, and threat model vs local stdio.

**Rationale:** Matches human/todo “Support HTTP Headers to act as a remote MCP Server” and common enterprise hosting patterns.

**Downsides:** High implementation and operational cost; remote MCP implies stronger hardening and governance than stdio-only local use.

**Confidence:** 70%

**Complexity:** High

**Status:** Unexplored

---

### 4. Contract-first testing and API health

**Description:** (a) Fixture and contract tests for path construction (including `sboms` pluralization), summarizers, and `items` vs `images` shapes; (b) optional CI checks against pinned OpenAPI fragments or snapshots for routes the MCP calls; (c) optional health-oriented tool or enhanced probes returning version/capability hints. Keep default CI mocked; live checks behind flags and secrets.

**Rationale:** Addresses human/todo “Higher robustness for tests to ensure API and response are healthy” and reduces silent breakage after Anchore upgrades.

**Downsides:** OpenAPI snapshots may churn; live verification needs stable credentials and environments.

**Confidence:** 80%

**Complexity:** Medium

**Status:** Unexplored

---

### 5. Bounded retry and backoff for idempotent GETs

**Description:** Extend the Anchore HTTP client with a documented retry policy: retryable statuses and network errors, jitter, and a global latency budget for safe GET operations; document relationship to current “no retry on timeout” behavior. Optional env tuning for operators.

**Rationale:** Directly matches human/todo “Graceful backoff for API calls”; reduces flaky agent runs against transient gateway or network failures.

**Downsides:** Retries can amplify load on an already unhealthy backend; must cap attempts and scope to idempotent methods only.

**Confidence:** 82%

**Complexity:** Low–Medium

**Status:** Unexplored

---

### 6. Operational clarity layer (correlation, account errors, digest normalization)

**Description:** Add a short correlation identifier per tool invocation in `context` and support-oriented stderr lines; improve messages for account-scoped failures when `x-anchore-account` is mis-set; share digest normalization helpers across list and SBOM flows where inputs vary (with/without `sha256:` prefix).

**Rationale:** Compounds ideas 2 and 5; speeds triage without changing Anchore semantics; must stay within R13/R14 rules.

**Downsides:** Touches shared formatting and error paths; avoid leaking secrets or raw tokens.

**Confidence:** 72%

**Complexity:** Low

**Status:** Unexplored

---

## Rejection Summary

| # | Idea | Reason rejected |
|---|------|-----------------|
| 1 | Generic “query DSL” without OpenAPI anchoring | Too vague; superseded by server-aligned filters (survivor 1). |
| 2 | Multiple duplicate “retry only” phrasings | Merged into survivor 5. |
| 3 | Single mega-tool bundling vuln + policy + SBOM + metadata | Large scope; overlaps existing tools; better as a later brainstorm variant. |
| 4 | Remediation handoff as ticket/export-only automation | Adjacent product; not in v2 todo; defer to brainstorm. |
| 5 | Streaming parse for very large JSON bodies | High cost and unclear MVP; defer past v2 core. |
| 6 | Circuit breaker after N failures | Useful optional follow-on; overlaps survivor 5; can ship after retry policy exists. |
| 7 | “Fossilize learnings” as a standalone feature | Already covered by AGENTS.md knowledge flow; not a product deliverable. |
| 8 | CI-only lint “default API must stay v2” | Small; fold into contract testing (survivor 4) rather than a separate star idea. |
| 9 | OpenAPI examples only in prose tool descriptions | Partially absorbed into survivor 4; weak alone. |

---

## Session Log

- 2026-04-03: Initial ideation — ~32 raw candidates generated across four ideation frames (pain/todo alignment, inversion/automation, leverage/compounding, reliability/edge cases), merged and adversarially filtered; **6** survivors retained; user confirmed candidate set; ideation artifact written under `docs/ideation/`.
- 2026-04-03: Brainstorm — survivor **#2** (tag-first / digest resolution UX); requirements captured in `docs/brainstorms/2026-04-03-image-reference-digest-resolution-requirements.md`; status updated to Explored.
