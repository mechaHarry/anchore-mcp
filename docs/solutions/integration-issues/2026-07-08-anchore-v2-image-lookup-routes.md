---
module: anchore-mcp
date: 2026-07-08
problem_type: integration_issue
component: tooling
severity: high
symptoms:
  - Exact tagged image lookup returns no match even though the image is analyzed
  - Registry and repository lookup returns unrelated rows or cannot select the newest analyzed tag
  - Requests rely on query parameters not documented for GET /v2/images
root_cause: wrong_api
resolution_type: code_fix
tags:
  - anchore-enterprise
  - api-v2
  - image-lookup
  - openapi
  - rest-query
---

# Anchore Enterprise image lookup routes depend on identifier and API version

## Context

Anchore’s per-image APIs are digest-keyed, while MCP callers commonly identify an image either by an exact tagged reference or by registry and repository components. Those two locator modes require different Anchore v2 list operations before downstream policy, vulnerability, SBOM, or detail calls can use a digest.

## Wrong behavior and symptoms

Two superficially similar implementations fail in different ways:

- Sending `fulltag=registry.example.com/team/app:1.0` to `/v2/images` uses the MCP convenience-field spelling as an undocumented wire parameter. A deployment may ignore it, reject it, or return a broad list instead of the exact tagged image.
- Sending `registry=registry.example.com&repository=team/app` to `/v2/images` assumes repository filters that are not portable for that operation. This can produce no match, unrelated candidates, or a misleading “newest” selection from locally filtered broad results.
- Trusting the backend full-tag filter without checking returned row metadata can attach an unrelated digest when a deployment ignores or loosely applies that filter.
- Calling `/v1/summaries/image-tags` merely because the v2 route exists assumes an unverified legacy capability.

The visible failure often appears later on a digest-keyed route, making the policy, vulnerability, or SBOM call look broken even though the lookup request selected the wrong digest or no digest at all.

## Root cause

The public MCP inputs were conflated with Anchore’s HTTP query contract:

- `anchore_list_images.fulltag` is a convenience name. Both the [current Anchore API specification](https://docs.anchore.com/current/docs/api/specs/anchore_api_swagger.yaml) and the [Anchore Enterprise 5.8 v2 specification](https://docs.anchore.com/5.8/docs/api/v2/specs/anchore_api_swagger.yaml) document `full_tag` for the v2 `GET /images` operation. Legacy v1 instead uses `fulltag`.
- The same specifications document separate `registry` and `repository` filters on `GET /summaries/image-tags`, together with its paged image-tag summary response. Those inputs are not a reason to assume equivalent fallback filters on `GET /images`.

The API documents describe shipped versions, but an installed deployment can differ. Its authenticated version-matched OpenAPI is authoritative for capabilities that are not fixed by the implemented v2 contract. OpenAPI is fetched from the configured origin with a bounded body and redirects disabled so another host or an unverified redirect cannot supply capability evidence.

## Resolution

Keep the public locator modes explicit and route each one independently:

1. For shared `image_reference="registry.example.com/team/app:1.0"` resolution, call `GET /v2/images?full_tag=registry.example.com%2Fteam%2Fapp%3A1.0`. In legacy v1 mode, call `GET /v1/images?fulltag=registry.example.com%2Fteam%2Fapp%3A1.0`. Treat the server filter only as narrowing: require exact reference evidence from each returned row before accepting its digest. Ignore unrelated rows. Bound row-evidence inspection and return `enumeration_incomplete` if evidence overflow could hide or follow an exact match; do not downgrade uncertainty to `no_match`. This shared resolver uses digest cardinality, not timestamps.
2. For `image_registry="registry.example.com"` plus `image_repository="team/app"` in v2, call the verified `GET /v2/summaries/image-tags?registry=registry.example.com&repository=team%2Fapp` route directly. Walk bounded `page`/`limit` responses and require the returned `full_tag` to match both components exactly.
3. In v1, fetch bounded `/v1/openapi.json` from the configured origin without following redirects. Call `/v1/summaries/image-tags` only if the document contains a `GET` operation under the prefixed `/v1/summaries/image-tags` or unprefixed `/summaries/image-tags` key with direct, non-`$ref` `registry` and `repository` query parameters. Otherwise return the static unsupported selection error and do not try the route.
4. Within `anchore_policy_blocking_vulnerabilities` only, fail newest selection closed unless every exact matching digest-bearing candidate has a reliable analysis timestamp (`analyzed_at` or an accepted equivalent). This applies to that tool’s `image_reference` and registry/repository locators. A missing, invalid, or untrusted timestamp prevents proof of the newest digest; digestless rows may be ignored; tied newest digests are errors.
5. Translate public `anchore_list_images.fulltag` to wire `full_tag` for v2 and retain wire `fulltag` for v1. Do not include `registry`, `repository`, or `repo` in the `/images` fallback allowlist; accept them only if the deployment OpenAPI explicitly advertises them for that operation.
6. Continue using bounded retry with backoff for the idempotent lookup GETs, and never log full backend bodies or credentials.

## Verification

- Shared exact-reference tests assert `/v2/images?full_tag=...` and `/v1/images?fulltag=...`, reject the opposite-version alias, require exact local evidence, reject unrelated digest rows, and return `enumeration_incomplete` for bounded evidence overflow.
- Registry/repository tests assert `/v2/summaries/image-tags` with both component filters, bounded `items`/`total_rows` pagination, exact component matching, and newest selection using reliable string or numeric analysis timestamps.
- V1 capability tests require a compatible prefixed or unprefixed OpenAPI path with direct filters, reject missing/`$ref` filters, fetch failures, and redirects, and prove that the summary route is not called without capability evidence.
- Policy-tool selection tests prove that a matching digest-bearing row with a missing, invalid, or untrusted timestamp fails closed while a matching digestless row may be ignored.
- List-image tests assert the version-specific public-`fulltag` translation and that registry/repository keys are absent from the static `/images` fallback allowlist.
- Run `uv run python scripts/check.py` and `git diff --check` before committing.
- For a live deployment, inspect the authenticated, version-matched OpenAPI document. V2 summary routing is already verified by the implemented contract; v1 must pass the explicit capability gate above.

## Related

- [Anchore API research notes](../../research/anchore-api-notes.md)
- [Image registry and repository lookup design](../../superpowers/specs/2026-07-07-image-registry-repository-lookup-design.md)

## References

- [Current Anchore API specification](https://docs.anchore.com/current/docs/api/specs/anchore_api_swagger.yaml)
- [Anchore Enterprise 5.8 v2 API specification](https://docs.anchore.com/5.8/docs/api/v2/specs/anchore_api_swagger.yaml)
- Deployment `GET /v1/openapi.json` or `GET /v2/openapi.json`, matching `ANCHORE_API_VERSION`
