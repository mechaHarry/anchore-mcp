# Anchore Enterprise API (research notes)

**Anchore Enterprise 5+** uses an explicit **`/v2/...`** path prefix. Unversioned or wrong-version paths may return **404** or **non-JSON** (HTML error pages), which breaks clients that expect JSON.

## OpenAPI on your deployment

Use the spec served by your Anchore API host, for example:

`GET https://<anchore-host>/v2/openapi.json`

That file is the source of truth for paths, query parameters, and response shapes.

## Auth

- **Basic** over HTTPS: username `_api_key` with password = API token (or per your org’s policy).
- **Account header**: `x-anchore-account: <account_name>` when using account-scoped resources.

## V2 (default in this MCP)

| Area | Method + path | Notes |
|------|----------------|-------|
| Images | `GET /v2/images` | List images; large lists may use an `items` array wrapper |
| Image vulns | `GET /v2/images/{image_digest}/vuln/all` | Vulnerability type `all`; see OpenAPI for other `vuln/{type}` routes |

## V1 (legacy)

Set environment variable `ANCHORE_API_VERSION=v1` if you must talk to older behavior. Example paths:

| Area | Method + path |
|------|----------------|
| Images | `GET /v1/images` |
| Image vulns | `GET /v1/images/{imageDigest}/vulnerabilities` |

## References

- [Migrating from API V1 to V2](https://docs.anchore.com/5.8/docs/api/v2/v1_migration/)
- [Anchore Enterprise API](https://docs.anchore.com/)
- Deployment **`/v2/openapi.json`** — source of truth for path/query/body
