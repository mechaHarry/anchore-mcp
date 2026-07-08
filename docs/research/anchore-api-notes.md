# Anchore Enterprise API (research notes)

**Anchore Enterprise 5+** uses an explicit **`/v2/...`** path prefix. Unversioned or wrong-version paths may return **404** or **non-JSON** (HTML error pages), which breaks clients that expect JSON.

## OpenAPI on your deployment

Use the spec served by your Anchore API host, for example:

`GET https://<anchore-host>/v2/openapi.json`

That file is the source of truth for paths, query parameters, and response shapes.

This MCP’s **`anchore_list_images`** tool uses **`list_query`** passthrough: allowlisted keys include the deployment’s `GET /v2/images` (or `/v1/images`) query parameters from OpenAPI (when `list_query` is used) plus a small static fallback set. The public `fulltag` convenience input has a version-specific wire key: v2 uses `full_tag`; v1 uses `fulltag`. The static fallback set intentionally does not assume that `registry`, `repository`, or `repo` filter `/images`; a deployment may use those keys there only when its OpenAPI explicitly advertises them. **GET** calls use bounded retries for transient failures — see `ANCHORE_HTTP_*` in README / `env.example`.

## Auth

- **Basic** over HTTPS: username `_api_key` with password = API token (or per your org’s policy).
- **Account header**: `x-anchore-account: <account_name>` when using account-scoped resources.

## V2 (default in this MCP)

| Area | Method + path | Notes |
|------|----------------|-------|
| Images | `GET /v2/images` | List images; exact tagged lookup uses query `full_tag=registry/repository:tag`; large lists may use an `items` array wrapper |
| Image tag summaries | `GET /v2/summaries/image-tags` | Registry/repository lookup uses separate `registry` and `repository` query parameters; response uses paged `items` plus `total_rows` |
| Image vulns | `GET /v2/images/{image_digest}/vuln/all` | Vulnerability type `all`; see OpenAPI for other `vuln/{type}` routes |
| Image SBOM | `GET /v2/images/{image_digest}/sboms/native-json` | Syft native JSON (“normal” mode in MCP) — segment is plural **`sboms`** |
| Image SBOM | `GET /v2/images/{image_digest}/sboms/spdx-json` | SPDX JSON |
| Image SBOM | `GET /v2/images/{image_digest}/sboms/cyclonedx-json` | CycloneDX JSON |
| Policy check | `GET /v2/images/{image_digest}/check` | Optional query: `tag`, `base_digest` — confirm on your OpenAPI |
| Image record | `GET /v2/images/{image_digest}` | Single-image metadata (fields vary by version) |

### Image lookup route distinction

Use the route that matches the identifier supplied by the MCP caller:

- `image_reference` is a fully qualified `registry/repository:tag`. Resolve only that exact tag with `GET /v2/images?full_tag=...`; legacy v1 uses `GET /v1/images?fulltag=...`. If multiple exact rows must be ordered, newest selection succeeds only if every exact matching digest-bearing candidate has a reliable analysis timestamp (`analyzed_at` or an accepted equivalent); matching digestless rows may be ignored. Then call the digest-keyed image route.
- `image_registry` plus `image_repository` is a component pair used by `anchore_policy_blocking_vulnerabilities`. Query `GET /v2/summaries/image-tags?registry=...&repository=...` and require an exact pair match. Newest selection succeeds only if every exact matching digest-bearing candidate has a reliable analysis timestamp (`analyzed_at` or an accepted equivalent) and one digest is provably newest. Any such candidate with a missing, invalid, or untrusted timestamp fails selection closed; matching digestless rows may be ignored.
- Do not emulate the second behavior with assumed `registry` or `repository` parameters on `GET /v2/images`. Those are not portable fallback filters for that operation.

Both the [current Anchore API specification](https://docs.anchore.com/current/docs/api/specs/anchore_api_swagger.yaml) and the [Anchore Enterprise 5.8 v2 specification](https://docs.anchore.com/5.8/docs/api/v2/specs/anchore_api_swagger.yaml) document `full_tag` on the v2 `/images` operation and the separate registry/repository filters on `/summaries/image-tags`. Legacy v1 uses `fulltag`. The deployment’s matching OpenAPI document remains authoritative because supported operations and response shapes can vary by installed version.

### SBOM path pitfall (400 Bad Request)

Enterprise **v2** OpenAPI lists image SBOMs under **`.../sboms/...`** (plural). Calling **`.../sbom/...`** (singular) can return **HTTP 400** with a non-obvious body. This MCP uses `/sboms/` for v2. **Source** repository SBOM routes in Anchore docs often use `/v2/sources/{id}/sbom/...` (singular) — image vs source paths are not interchangeable; always confirm on `GET /v2/openapi.json`.

## V1 (legacy)

Set environment variable `ANCHORE_API_VERSION=v1` if you must talk to older behavior. Example paths:

| Area | Method + path |
|------|----------------|
| Images | `GET /v1/images` (`fulltag=...` for exact tagged lookup) |
| Image vulns | `GET /v1/images/{imageDigest}/vulnerabilities` |

## References

- [Migrating from API V1 to V2](https://docs.anchore.com/5.8/docs/api/v2/v1_migration/)
- [Current Anchore API specification](https://docs.anchore.com/current/docs/api/specs/anchore_api_swagger.yaml)
- [Anchore Enterprise 5.8 v2 API specification](https://docs.anchore.com/5.8/docs/api/v2/specs/anchore_api_swagger.yaml)
- Deployment **`/v2/openapi.json`** — source of truth for path/query/body
