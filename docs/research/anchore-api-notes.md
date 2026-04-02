# Anchore Enterprise API (research notes)

Used to pick routes for the MCP tools. **Confirm against your deployment’s Swagger** (`/v1/swagger.json` or `/swagger.json` per install).

## Auth

- **Basic** over HTTPS: username often `_api_key` with password = static API token (or user/password per policy).
- **Account header**: `x-anchore-account: <account_name>` when using account-scoped resources.

## Candidate endpoints (typical v1)

| Area | Method + path | Notes |
|------|----------------|-------|
| Health | `GET /health` | Liveness; no auth in many installs |
| System | `GET /v1/system` | Version/status |
| Images | `GET /v1/images` | List images (query params for filters) |
| Image | `GET /v1/images/{imageDigest}` | Single image by digest |
| Image vulns | `GET /v1/images/{imageDigest}/vulnerabilities` | CVE list for image |
| Image policy | `GET /v1/images/{imageDigest}/check` or policy eval endpoints | Policy status (confirm path) |
| Policies | `GET /v1/policies` | List policies |
| Policy bundles | `GET /v1/policies/{policyId}` | Detail |
| Feeds / sync | `GET /v1/system/feeds` | Feed sync status |
| Registry creds | `GET /v1/credentials` | If exposed (sensitive; tools must redact) |

Exact paths may differ by **Anchore Enterprise** minor version; validate before implementing tools.

## References

- [Anchore Enterprise API](https://docs.anchore.com/) — official docs
- Deployment Swagger URL — source of truth for path/query/body
