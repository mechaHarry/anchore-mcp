# Anchore Enterprise API (research notes)

**Anchore Enterprise 5+** uses an explicit **`/v2/...`** path prefix. Unversioned or wrong-version paths may return **404** or **non-JSON** (HTML error pages), which breaks clients that expect JSON.

## OpenAPI on your deployment

Use the spec served by your Anchore API host, for example:

`GET https://<anchore-host>/v2/openapi.json`

That file is the source of truth for paths, query parameters, and response shapes. OpenAPI retrieval is same-origin with the configured `ANCHORE_URL`, size-bounded, and uses no-follow redirect handling; a redirect or fetch failure is not treated as capability proof.

This MCP’s **`anchore_list_images`** tool uses **`list_query`** passthrough: allowlisted keys include the deployment’s `GET /v2/images` (or `/v1/images`) query parameters from OpenAPI (when `list_query` is used) plus a small static fallback set. The public `fulltag` convenience input has a version-specific wire key: v2 uses `full_tag`; v1 uses `fulltag`. The static fallback set intentionally does not assume that `registry`, `repository`, or `repo` filter `/images`; a deployment may use those keys there only when its OpenAPI explicitly advertises them. **GET** calls use bounded retries for transient failures — see `ANCHORE_HTTP_*` in README / `env.example`.

## Auth

- **Basic** over HTTPS: username `_api_key` with password = API token (or per your org’s policy).
- **Account header**: `x-anchore-account: <account_name>` when using account-scoped resources.

## V2 (default in this MCP)

| Area | Method + path | Notes |
|------|----------------|-------|
| Images | `GET /v2/images` | List images; exact tagged lookup uses query `full_tag=registry/repository:tag`; large lists may use an `items` array wrapper |
| Image tag summaries | `GET /v2/summaries/image-tags` | Verified v2 registry/repository route; called directly with separate `registry` and `repository` parameters; response uses paged `items` plus `total_rows` |
| Image vulns | `GET /v2/images/{image_digest}/vuln/all` | Vulnerability type `all`; see OpenAPI for other `vuln/{type}` routes |
| Image SBOM | `GET /v2/images/{image_digest}/sboms/native-json` | Syft native JSON (“normal” mode in MCP) — segment is plural **`sboms`** |
| Image SBOM | `GET /v2/images/{image_digest}/sboms/spdx-json` | SPDX JSON |
| Image SBOM | `GET /v2/images/{image_digest}/sboms/cyclonedx-json` | CycloneDX JSON |
| Policy check | `GET /v2/images/{image_digest}/check` | Optional query: `tag`, `base_digest` — confirm on your OpenAPI |
| Image record | `GET /v2/images/{image_digest}` | Single-image metadata (fields vary by version) |

### Image lookup route distinction

Use the route that matches the identifier supplied by the MCP caller:

- Shared `image_reference` resolution uses a fully qualified `registry/repository:tag`. It queries `GET /v2/images?full_tag=...`; legacy v1 uses `GET /v1/images?fulltag=...`. A loose or ignored backend filter is not proof: the resolver accepts a digest only from a row whose bounded local metadata contains the exact requested reference. Unrelated digest rows are ignored. If pagination or reference-evidence bounds prevent a complete proof, the result is explicit `enumeration_incomplete`, never `no_match` based on unseen evidence. The shared resolver uses 0/1/N digest cardinality and does not use timestamps or choose a newest image.
- `image_registry` plus `image_repository` is a component pair used by `anchore_policy_blocking_vulnerabilities`. V2 calls `GET /v2/summaries/image-tags?registry=...&repository=...` directly and requires an exact pair match. V1 calls `/v1/summaries/image-tags` only after `/v1/openapi.json` advertises a `GET` operation under `/v1/summaries/image-tags` or `/summaries/image-tags` with direct, non-`$ref` `registry` and `repository` query parameters. Missing, ambiguous, redirected, or unavailable OpenAPI capability evidence returns a static unsupported selection error without calling the summary route.
- Do not emulate the second behavior with assumed `registry` or `repository` parameters on `GET /v2/images`. Those are not portable fallback filters for that operation.

Within `anchore_policy_blocking_vulnerabilities` only, both exact `image_reference` and registry/repository selection choose the newest matching digest. Every exact matching digest-bearing candidate must have a reliable analysis timestamp (`analyzed_at` or an accepted equivalent); missing, invalid, or untrusted timestamp evidence fails closed, while digestless rows may be ignored. Ties across newest digests are errors.

Both the [current Anchore API specification](https://docs.anchore.com/current/docs/api/specs/anchore_api_swagger.yaml) and the [Anchore Enterprise 5.8 v2 specification](https://docs.anchore.com/5.8/docs/api/v2/specs/anchore_api_swagger.yaml) document `full_tag` on the v2 `/images` operation and the separate registry/repository filters on `/summaries/image-tags`. Legacy v1 uses `fulltag`. The deployment’s matching OpenAPI document remains authoritative because supported operations and response shapes can vary by installed version.

### SBOM path pitfall (400 Bad Request)

Enterprise **v2** OpenAPI lists image SBOMs under **`.../sboms/...`** (plural). Calling **`.../sbom/...`** (singular) can return **HTTP 400** with a non-obvious body. This MCP uses `/sboms/` for v2. **Source** repository SBOM routes in Anchore docs often use `/v2/sources/{id}/sbom/...` (singular) — image vs source paths are not interchangeable; always confirm on `GET /v2/openapi.json`.

## V1 (legacy)

Set environment variable `ANCHORE_API_VERSION=v1` if you must talk to older behavior. Example paths:

| Area | Method + path |
|------|----------------|
| Images | `GET /v1/images` (`fulltag=...` for exact tagged lookup) |
| Image tag summaries | `GET /v1/summaries/image-tags` only after `/v1/openapi.json` explicitly proves the compatible `GET` filters described above |
| Image vulns | `GET /v1/images/{imageDigest}/vulnerabilities` |

## References

- [Migrating from API V1 to V2](https://docs.anchore.com/5.8/docs/api/v2/v1_migration/)
- [Current Anchore API specification](https://docs.anchore.com/current/docs/api/specs/anchore_api_swagger.yaml)
- [Anchore Enterprise 5.8 v2 API specification](https://docs.anchore.com/5.8/docs/api/v2/specs/anchore_api_swagger.yaml)
- Deployment **`/v1/openapi.json`** or **`/v2/openapi.json`** matching `ANCHORE_API_VERSION` — source of truth for deployment-specific capabilities
