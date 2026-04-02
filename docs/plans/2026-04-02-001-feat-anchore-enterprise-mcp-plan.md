---
title: "feat: Anchore Enterprise MCP (read paths, profiles, remediation handoff)"
type: feat
status: active
date: 2026-04-02
origin: docs/brainstorms/2026-04-02-anchore-enterprise-mcp-requirements.md
revised: 2026-04-02
---

# feat: Anchore Enterprise MCP (read paths, profiles, remediation handoff)

## Overview

Deliver a **local stdio MCP server** that connects assistants to **Anchore Enterprise** using **named profiles**, exposes **read-only** vulnerability and image correlation plus **SBOM/report retrieval**, and provides a **documented remediation handoff bundle** for downstream automation.

**Operator model (R8):** Every tool surfaces **non-secret context** (profile name, HTTPS base URL, account name when set, intended action) in the tool result. **No** custom **preview → confirm → execute** loop in this process. **MCP elicitation** and **host IDE** safety UX own approval; document variance in `AGENTS.md` without prescribing a specific product.

**Privacy model (R13–R14):** **stderr** must use **secret/header redaction** only; **PII in IDE logs and persisted history** is **out of scope** for this server. **R14** applies only to **textual** content this MCP returns in **chat tool results** (mask + explicit warning when heuristics match). **JSON** payloads returned to the client need not be masked, provided they are **not** written to MCP operational logs. **Downloaded files** may remain **unmasked**. No `pii_ok`-style flags.

**Non-goals:** Remediation execution, **CI/CD orchestration** inside this repo, image upload / scan trigger (R9), and mandatory integrations beyond in-scope MCP behavior (R10).

This plan implements **R1–R15** as defined in the origin document (see [Requirements Trace](#requirements-trace)); it does not expand product scope.

## Problem Frame

Security/AppSec and SRE users need Anchore-backed truth inside assistant workflows without ad hoc scripts. The MCP is a **read-focused integration layer** and a **remediation handoff producer**; remediation, **CI/CD orchestration**, and image rebuilds stay **external** (see origin: [docs/brainstorms/2026-04-02-anchore-enterprise-mcp-requirements.md](docs/brainstorms/2026-04-02-anchore-enterprise-mcp-requirements.md)).

**R2 (scheduled / batch):** Repeatable fleet-style use is a **first-class** scenario. **Non-interactive** clients may invoke tools without human confirmation; that path is **host-dependent** (no MCP-side block). The MCP still surfaces **R8** context in every response so automation can log or assert the correct profile.

## Success Criteria (from origin)

The implementation should make these outcomes achievable (see origin § Success Criteria):

- AppSec triage loop (CVE understanding → SBOM/report evidence → **remediation handoff**) **without** Anchore UI for those steps.
- SRE/automation: **repeatable** queries per profile and **handoff payloads** for periodic review and downstream routing.
- **Profile** switching via **default** + **override** is predictable.
- **R8:** Enough **non-secret context** per call; confirmation is **IDE/elicitation**, not in-server.
- **R11:** Install, configure, and extend using **repository docs** and obvious config patterns.

## Requirements Trace

| ID | Plan obligation |
|----|-----------------|
| **R1** | Tool naming, descriptions, and defaults favor **Security/AppSec** triage and investigation. |
| **R2** | Tools and outputs support **idempotent, scriptable** use; document non-interactive invocation; same **R8** context in automated calls. |
| **R3** | Multiple **named profiles** per install; each: **HTTPS base URL**, **API token** auth per R12; optional **account name**; validate Anchore behavior when omitted. |
| **R4** | **Active default** profile + **optional per-tool `profile` override**; clear errors for unknown profile. |
| **R5** | Read tools: CVE/image correlation within **Anchore Enterprise API** capabilities (exact routes deferred). |
| **R6** | SBOM **JSON** only: modes **normal**, **SPDX**, **CycloneDX**; exports: **Policy Compliance Export**, **Vulnerability Export**, **Build Summary** (+ manifest/Dockerfile/History where API provides); **R15** size surfaced; additional read exports allowed if consistent with R12–R15. |
| **R7** | Dedicated **remediation handoff** tool + **versioned JSON** schema doc; **no** source-repo routing claims. |
| **R8** | **Context block** on every Anchore query/export tool; **no** bespoke confirm loop; **AGENTS.md** documents elicitation vs IDE. |
| **R9** | No upload/trigger-scan tools in v1. |
| **R10** | No product-scope integrations beyond this MCP’s tools and docs. |
| **R11** | `README.md`, `AGENTS.md`, `docs/remediation-handoff-schema.md`, pointer to `docs/research/anchore-api-notes.md` when it exists. |
| **R12** | **HTTPS**; **`username`** = literal **`_api_key`** when **`password`** holds API token; optional account name. |
| **R13** | No secrets in repo; config from env/files; **stderr** secret redaction; **no** MCP responsibility for IDE-held PII. |
| **R14** | **Textual** tool strings: mask + warning when PII detected; **JSON** to client unmasked if **not** logged by MCP; **files** may be raw; document in `AGENTS.md`. |
| **R15** | Size metadata on large exports; bounding policy explicit in tool docs before truncation. |

## Scope Boundaries

- No remediation execution, patching, or image rebuild inside this repo.
- **This MCP does not orchestrate CI/CD** (pipelines are external).
- No image upload or scan-trigger tools in v1 (R9).
- No mandatory integrations outside in-scope MCP behavior (R10).

## Context & Research

### Relevant Code and Patterns

- **Greenfield** — no application source yet. This plan defines **TypeScript** layout, `src/` boundaries, and test locations. Docs present: origin brainstorm, this plan.

### Institutional Learnings

- No `docs/solutions/` entries in this repo yet.

### External References

- Anchore Enterprise REST API: [Anchore API reference](https://docs.anchore.com/current/docs/api/reference/) — map routes and Enterprise version during implementation; record in `docs/research/anchore-api-notes.md`.
- MCP TypeScript SDK: [Model Context Protocol TypeScript SDK](https://modelcontextprotocol.github.io/typescript-sdk/) — `McpServer`, `StdioServerTransport`, schema-backed tools.
- MCP security: **stdio** for local use; validate tool inputs; **stdout** = MCP only, **stderr** = logs.

## Key Technical Decisions

- **Stack:** **Node.js (LTS)** + **TypeScript** + `@modelcontextprotocol/sdk` + **Zod** for tool inputs. Rationale: MCP ecosystem, schema-first tools, easy stdio deployment.

- **Transport:** **Stdio only** for v1 (no HTTP listener on the MCP process).

- **Protocol:** All MCP JSON-RPC on **stdout**; **stderr** only for logging (R13).

- **Profiles:** File-based config (YAML or JSON per resolved planning note), XDG-style default path; override via env e.g. `ANCHORE_MCP_CONFIG`; tokens via env reference or gitignored secrets file.

- **Anchore client:** Thin `fetch`-based HTTPS layer; Basic auth using **`_api_key`** / token per R12; optional **Account** header or query per Anchore Enterprise docs (validate in implementation).

- **Tool result shape (R8 + R14):** Structured pattern: **`context`** (profile, baseUrl, account?, action summary) + **`content`** (text and/or JSON string for chat) + optional **`warnings`** array. **Textual** segments pass through **PII** mask/warn; **JSON** segments are not duplicated to stderr. Ensures R8 visibility without a second confirmation round-trip.

- **PII (R14):** Implement **textual** detection/masking in **`src/pii/`** before feature tools depend on it (see Unit 4 ordering below). **JSON-in-chat** returned as tool content **without** masking per requirements, provided implementation **never logs** full JSON bodies to stderr.

- **Remediation handoff:** One primary tool returning **versioned JSON** + `docs/remediation-handoff-schema.md`; no repo routing fields required (R7).

- **Testing:** Unit tests with mocked HTTP; optional live test behind env flag; default CI **no** live Anchore.

## Open Questions

### Resolved During Planning

- **Config format:** YAML or JSON with Zod schema; YAML preferred for multi-profile readability.
- **R6 scope:** SBOM modes and named exports as in origin; extra read-only exports from API discovery allowed if aligned with R12–R15.
- **R7:** Handoff does not resolve source repos; consumers add org metadata.
- **R8:** Context in every response; no two-phase confirm tool.
- **R12 `username`:** Literal `_api_key` when password is the API token.

### Deferred to Implementation

- **Anchore Enterprise** OpenAPI paths, query params, and **minimum version** (from [docs/research/anchore-api-notes.md](docs/research/anchore-api-notes.md)).
- **Account name** empty vs omitted — exact HTTP behavior per Anchore version.
- **Pagination** for large image lists — expose tool params if needed after integration testing.
- **PII heuristics** — specific patterns and false-positive handling (document limits in `AGENTS.md`).
- **Large payload** strategy — inline vs temp file path for SBOM (R15 must not surprise users).
- **Release packaging** (`npm publish`, bundled binary) — post-v1 optional.

### Carried From Origin (Deferred to Planning / Implementation)

These originate from the brainstorm “Deferred to Planning” list and are satisfied by this plan’s units or the implementation notes above:

- Map **API operations** to tools and handoff schema (Units 3–6 + research doc).
- Map **SBOM modes and exports** to endpoints (Units 3, 5 + research doc).
- **Profile storage** format and **account name** semantics (Unit 2 + research).
- **Elicitation / tool descriptions** for R8 (Unit 7 `AGENTS.md`).
- **PII** textual vs JSON, **no JSON in stderr logs**, **warnings**, **size limits** (Units 4–6, 8).

## High-Level Technical Design

> *Directional guidance for review, not implementation specification.*

```mermaid
sequenceDiagram
  participant C as MCP client
  participant S as MCP server
  participant P as Profile resolver
  participant A as Anchore Enterprise API

  C->>S: tool call + optional profile override
  S->>P: resolve profile (default or override)
  P-->>S: base URL + auth binding
  S->>A: HTTPS REST request
  A-->>S: JSON or binary payload
  S-->>C: context + content (R8); textual segments via R14 mask/warn; JSON per R14
```

**Profile resolution:** Tool `profile` argument wins; else **active default**; error if missing or unknown.

**R2 / headless:** Same sequence without a human step; **R8** context still returned for auditability.

## Implementation Units

- [x] **Unit 1: Repository and MCP bootstrap**

**Goal:** Runnable **stdio** MCP server, lint/tsconfig baseline, smoke tool (e.g. list profile **names** + active default) proving wiring.

**Requirements:** Foundation for R3–R4, R13 (stderr-only logging discipline).

**Dependencies:** None.

**Files:**
- Create: `package.json`, `tsconfig.json`, `src/index.ts`, `src/mcp/server.ts`, `.gitignore`, `.nvmrc` or `engines`
- Test: `src/mcp/server.test.ts`

**Approach:**
- `StdioServerTransport` + minimal tool registration; logger writes **stderr** only.

**Test scenarios:**
- **Happy path:** Server starts; stdout carries only MCP traffic (mock or spy).
- **Error path:** Startup failure emits actionable message on stderr, no garbage on stdout.

**Verification:** Test command documented in README passes locally.

---

- [ ] **Unit 2: Profile configuration model**

**Goal:** Load **multiple profiles**, **default** + **override** resolution, credentials via **secure binding** (no secrets in git).

**Requirements:** R3, R4, R12, R13.

**Dependencies:** Unit 1.

**Files:**
- Create: `src/config/profiles.ts`, `src/config/schema.ts`, `config.example.yaml`, `src/config/profiles.test.ts`
- Modify: `src/index.ts`

**Approach:**
- Zod-validated config: `profiles.<name>.baseUrl`, `username` (`_api_key` for token auth), `password` from env, optional `account`; document `ANCHORE_MCP_CONFIG` (or chosen env name).

**Test scenarios:**
- **Happy path:** Multiple profiles; override selects non-default.
- **Edge case:** Unknown profile → clear tool-level error.
- **Error path:** Missing credential env → message without printing secret values.

**Verification:** Unit tests cover resolution matrix.

---

- [ ] **Unit 3: Anchore HTTP client**

**Goal:** Shared HTTPS client: timeouts, auth header construction, status mapping, **no sensitive data on stderr** (raw bodies).

**Requirements:** R5, R6, R12, R13.

**Dependencies:** Unit 2.

**Files:**
- Create: `src/anchore/client.ts`, `src/anchore/errors.ts`, `src/anchore/client.test.ts`

**Approach:**
- Mocked `fetch` in tests. Time-boxed research captured in `docs/research/anchore-api-notes.md`.

**Test scenarios:**
- **Happy path:** 200 + JSON.
- **Error path:** 401/403 → safe user message (no token echo).
- **Error path:** Timeout → documented behavior (single policy, no retry or bounded retry — pick one and document).

**Verification:** Mock tests green; notes list candidate endpoints for Units 5–6.

---

- [ ] **Unit 4: PII text handling + safe logging primitives**

**Goal:** Centralize **R14** (**textual** mask + warning) and **R13** (**stderr** secret redaction). **Do not** log full JSON tool payloads to stderr. Downstream tools **compose** context + content through these helpers.

**Requirements:** R13 (logging), R14 (core behavior).

**Dependencies:** Unit 1 (logging pattern); consumed by Units 5–7.

**Files:**
- Create: `src/logging/safe-log.ts`, `src/logging/safe-log.test.ts`, `src/pii/mask.ts`, `src/pii/warn.ts`, `src/pii/text.test.ts` (or `pii/mask.test.ts`, `pii/warn.test.ts`)
- Optional: `src/tools/context.ts` — **R8** context string or object builder used by all Anchore tools

**Approach:**
- `safe-log`: redact `Authorization`, bearer tokens, known patterns; never log full API response bodies at info level (debug policy documented).
- `mask` / `warn`: input **textual** segments only; return masked text + warning list when heuristics match.
- Document: **JSON** strings returned to the client are **not** passed through mask; they must not be **logged** wholesale.

**Test scenarios:**
- **Error path:** 401 log line contains no token substring.
- **Happy path:** Textual PII-like fixture → masked output + warning present.
- **Happy path:** JSON string is not written to stderr by helper paths used in tests.

**Verification:** Unit tests cover redaction and textual PII path; aligns with origin R14.

---

- [ ] **Unit 5: Tools — vulnerabilities and images (read)**

**Goal:** **R5** tools — CVE query by image/artifact; list/search images by vulnerability criteria per API support.

**Requirements:** R5, R8, R14.

**Dependencies:** Units 3–4.

**Files:**
- Create: `src/tools/vulnerabilities.ts`, `src/tools/images.ts`, `src/tools/vulnerabilities.test.ts`, `src/tools/images.test.ts`
- Modify: MCP registration module

**Approach:**
- Narrow tools (no monolithic “everything” tool).
- Every result includes **R8** context via shared helper.
- **R14:** Apply mask/warn to **textual** summaries only; JSON results as tool content per R14; use Unit 4 helpers.

**Test scenarios:**
- **Happy path:** Mocked Anchore returns vulnerabilities + **context** fields.
- **Edge case:** Empty result set, explicit messaging.
- **R14:** Textual summary line triggers mask + warning; JSON not logged to stderr.
- **Integration (optional):** Skipped live test behind `ANCHORE_LIVE_TEST=1`.

**Verification:** Mocked tests green; manual MCP invocation documented.

---

- [ ] **Unit 6: Tools — SBOM and reports (read)**

**Goal:** **R6** — SBOM (**normal** / **SPDX** / **CycloneDX**) + named exports + sub-parts where available. **R15** size everywhere; **R8** context.

**Requirements:** R6, R8, R14, R15.

**Dependencies:** Units 3–5 patterns.

**Files:**
- Create: `src/tools/sbom.ts`, `src/tools/sbom.test.ts`, `src/tools/reports.ts` (or split by export type if cleaner), matching tests
- Modify: MCP registration module

**Approach:**
- Always include **size** (bytes or human-readable) before or beside payload reference.
- Large responses: document truncation, temp file path, or chunking **before** user commits — no silent truncation.

**Test scenarios:**
- **Happy path:** SBOM JSON for mocked image + size metadata.
- **Edge case:** Oversized response follows documented policy from tool description.
- **R15:** Size surfaced even when payload is abbreviated.

**Verification:** Tests avoid OOM in CI; policy explicit in tool docs.

---

- [ ] **Unit 7: Remediation handoff tool and schema documentation**

**Goal:** **R7** + **R11** — dedicated handoff tool, **versioned JSON**, `docs/remediation-handoff-schema.md`.

**Requirements:** R7, R8, R11, R14.

**Dependencies:** Units 3–6.

**Files:**
- Create: `src/tools/remediation-handoff.ts`, `src/tools/remediation-handoff.test.ts`, `docs/remediation-handoff-schema.md`
- Modify: `AGENTS.md` (link to schema)

**Approach:**
- Fields: profile, base URL (non-secret), image IDs, vuln/package evidence, fix hints from Anchore; **handoffVersion**; **no** mandatory repo fields.
- **R14:** Textual adjuncts masked; JSON body policy same as other tools.

**Test scenarios:**
- **Happy path:** Golden snapshot against mocked composite Anchore response (snapshot reflects **chat** JSON as returned, not stderr).
- **Edge case:** Valid schema without repo-mapping fields.

**Verification:** Schema doc matches TypeScript/types or examples in repo.

---

- [ ] **Unit 8: Documentation, CI, and quality gate**

**Goal:** **R11** complete README + `AGENTS.md`; **npm scripts** `lint`, `typecheck`, `test`; optional `.github/workflows/ci.yml`; final pass that **R13** redaction and **R14** “no JSON on stderr” invariants hold across tools.

**Requirements:** R11; operational clarity for R12–R15; repo hygiene.

**Dependencies:** Units 1–7.

**Files:**
- Create: `README.md`, `AGENTS.md`, `.github/workflows/ci.yml` (if GitHub Actions used)
- Modify: any gaps in cross-links

**Approach:**
- README: install, stdio MCP config example (Cursor / Claude Desktop style), **no secrets in examples**.
- AGENTS.md: architecture, **R8** vs IDE, **R14** textual vs JSON vs files, **R15** size, how to add tools, testing commands, link `docs/research/anchore-api-notes.md` and handoff schema.
- CI: lint + typecheck + test on PR; if no Actions, document local-only workflow.

**Test expectation:** none — documentation and pipeline config.

**Verification:** New contributor can install from README; CI or documented equivalent runs green.

## System-Wide Impact

- **Interaction graph:** **Profile resolver** → **Anchore client** → tool handler → **R8** context + **R14** on **textual** segments → MCP response. Handoff tool may call client multiple times.
- **Error propagation:** User-facing errors short and non-leaking; optional `details` only when safe.
- **State:** No server-side cache in v1 unless justified later.
- **Invariants:** **stdout** = MCP only; **stderr** = logs with **R13** redaction; **R14** JSON not duplicated on stderr.

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| Anchore Enterprise API drift by version | Research doc + minimum version in README; optional live tests behind flag |
| Secret leakage on stderr | `safe-log` tests; code review on any new log line |
| IDE vs MCP confusion (R8) | Explicit README + AGENTS sections |
| Large SBOM blow assistant context | R15 size + truncation/file policy in tool docs |
| Write-path scope creep | PR review against R9 |

## Documentation / Operational Notes

- `docs/remediation-handoff-schema.md` — downstream automation contract.
- `docs/research/anchore-api-notes.md` — version-specific Anchore mapping (created during Unit 3+).
- Service account tokens: treat as production secrets (R12–R13).

## Sources & References

- **Origin document:** [docs/brainstorms/2026-04-02-anchore-enterprise-mcp-requirements.md](docs/brainstorms/2026-04-02-anchore-enterprise-mcp-requirements.md)
- **External:** [Anchore API reference](https://docs.anchore.com/current/docs/api/reference/), [MCP TypeScript SDK](https://modelcontextprotocol.github.io/typescript-sdk/)
