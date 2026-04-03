# Remediation handoff JSON (R7)

Versioned bundle produced by the MCP tool **`anchore_remediation_handoff`**. Downstream automation (ticketing, rebuild pipelines, patch trackers) should treat this as **evidence from Anchore**, not as execution instructions. **No** source-repository routing fields are required; consumers attach org/repo metadata themselves.

## Wire format (MCP tool text content)

The tool returns the same **R8 + R14** wrapper as other Anchore tools (see `src/tools/format.ts`):

| Field | Meaning |
|--------|---------|
| `context` | Non-secret scope: `baseUrl`, optional `account`, `apiVersion`, `action`, `summaryLine` |
| `summary` | R14-masked textual summary |
| `warnings` | R14 warnings when textual heuristics match |
| `sizeBytes` | R15 — sum of UTF-8 body sizes of bundled Anchore HTTP responses |
| `anchore` | **Remediation handoff bundle** (schema below) |

`anchore` in that wrapper is the composite payload documented here — not a single raw API response.

## Bundle schema (`anchore` object)

### `handoffVersion`

- **Type:** string
- **Current:** `1.0.0` (see `REMEDIATION_HANDOFF_VERSION` in `src/tools/remediation-handoff.ts`)
- **Rule:** Bump when you make breaking changes to required fields or semantics.

### `generatedAt`

- **Type:** string, ISO 8601 timestamp (UTC recommended)

### `deployment`

Non-secret Anchore scope (R8):

| Field | Type | Required |
|-------|------|----------|
| `baseUrl` | string (HTTPS) | Yes |
| `account` | string | No — when `x-anchore-account` was configured |
| `apiVersion` | `"v1"` \| `"v2"` | Yes |

### `imageDigest`

- **Type:** string  
- **Meaning:** Image digest passed to the tool (e.g. `sha256:…`), used as the correlation key for all evidence.

### `evidence`

Anchore API payloads and R15 sizes. Exact JSON shapes depend on your Anchore Enterprise version; confirm with `https://<host>/v2/openapi.json`.

| Field | Type | Meaning |
|-------|------|---------|
| `imageDetail` | unknown | Body of `GET /v2/images/{digest}` (or v1 equivalent) |
| `imageDetailSizeBytes` | number | UTF-8 byte length of that response |
| `vulnerabilities` | unknown | Body of `GET .../vuln/all` (v2) or `.../vulnerabilities` (v1) |
| `vulnerabilitiesSizeBytes` | number | UTF-8 byte length |
| `policyCheck` | unknown | Present when `include_policy_check` is true — body of `GET .../check` |
| `policyCheckSizeBytes` | number | Present with `policyCheck` |

When `include_policy_check` is **false**, `policyCheck` and `policyCheckSizeBytes` are omitted.

## Non-goals

- No guaranteed fix/version pins — use vulnerability and image metadata inside `evidence` per your process.
- No mandatory CI or repo identifiers in v1.

## References

- Plan: [docs/plans/2026-04-02-001-feat-anchore-enterprise-mcp-plan.md](plans/2026-04-02-001-feat-anchore-enterprise-mcp-plan.md)
- API mapping: [docs/research/anchore-api-notes.md](research/anchore-api-notes.md)
