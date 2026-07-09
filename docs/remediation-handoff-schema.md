# Remediation handoff structured content

`anchore_remediation_handoff` returns a versioned bundle of Anchore evidence. It is not a remediation command, patch prescription, source-repository routing instruction, or authorization to change another system.

The concise MCP text content is PII-masked. The structured evidence documented here is intentionally unmasked so downstream software can interpret the original Anchore response. Treat it as sensitive data and do not copy it wholesale into logs, prompts, or tickets.

## Current contract: `2.0.0`

The tool’s `structuredContent` has this shape:

```json
{
  "handoffVersion": "2.0.0",
  "generatedAt": "2026-07-08T12:00:00Z",
  "deployment": {
    "baseUrl": "https://anchore.example",
    "account": null,
    "apiVersion": "v2"
  },
  "imageDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "selection": {
    "complete": true,
    "pages_fetched": 0,
    "reason": null
  },
  "evidence": {
    "detail": {"data": {}, "sizeBytes": 2},
    "vulnerabilities": {"data": {"items": []}, "sizeBytes": 12},
    "policy": {"data": {"status": "green"}, "sizeBytes": 18}
  },
  "totalSizeBytes": 32,
  "context": {
    "base_url": "https://anchore.example",
    "account": null,
    "api_version": "v2",
    "action": "remediation handoff"
  },
  "warnings": []
}
```

Required bundle fields are `handoffVersion`, `generatedAt`, `deployment`, `imageDigest`, `selection`, `evidence`, `totalSizeBytes`, `context`, and `warnings`.

`deployment` contains `baseUrl`, optional `account`, and `apiVersion`. `generatedAt` is an ISO 8601 timestamp. `totalSizeBytes` is the sum of the included Anchore HTTP response body sizes.

`evidence.detail` and `evidence.vulnerabilities` are always present. Each evidence entry is exactly `{data, sizeBytes}`: `data` is the raw JSON response and `sizeBytes` is its observed UTF-8 response-body length. `evidence.policy` has the same shape when `include_policy_check` is true. When policy is disabled, the `policy` key is omitted entirely; it is not emitted as `null`.

Exact evidence payload shapes vary by Anchore version. Confirm them with the configured deployment’s same-origin, version-matched OpenAPI document.

Breaking required-field or semantic changes require a new `handoffVersion`.

## Non-goals

- No guaranteed fix version or patch instruction
- No mandatory organization, repository, ticket, or CI identifiers
- No permission to execute a destructive operation

## References

- [Anchore API research notes](research/anchore-api-notes.md)
- [Python FastMCP rewrite design](superpowers/specs/2026-07-08-python-fastmcp-rewrite-design.md)
