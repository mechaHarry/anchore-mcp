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

# Anchore Enterprise v2 image lookup routes depend on the identifier

## Context

Anchore’s per-image APIs are digest-keyed, while MCP callers commonly identify an image either by an exact tagged reference or by registry and repository components. Those two locator modes require different Anchore v2 list operations before downstream policy, vulnerability, SBOM, or detail calls can use a digest.

## Wrong behavior and symptoms

Two superficially similar implementations fail in different ways:

- Sending `fulltag=registry.example.com/team/app:1.0` to `/v2/images` uses the MCP convenience-field spelling as an undocumented wire parameter. A deployment may ignore it, reject it, or return a broad list instead of the exact tagged image.
- Sending `registry=registry.example.com&repository=team/app` to `/v2/images` assumes repository filters that are not portable for that operation. This can produce no match, unrelated candidates, or a misleading “newest” selection from locally filtered broad results.

The visible failure often appears later on a digest-keyed route, making the policy, vulnerability, or SBOM call look broken even though the lookup request selected the wrong digest or no digest at all.

## Root cause

The public MCP inputs were conflated with Anchore’s HTTP query contract:

- `anchore_list_images.fulltag` is a convenience name, not the wire spelling. Both the [current Anchore API specification](https://docs.anchore.com/current/docs/api/specs/anchore_api_swagger.yaml) and the [Anchore Enterprise 5.8 v2 specification](https://docs.anchore.com/5.8/docs/api/v2/specs/anchore_api_swagger.yaml) document `full_tag` for `GET /images`.
- The same specifications document separate `registry` and `repository` filters on `GET /summaries/image-tags`, together with its paged image-tag summary response. Those inputs are not a reason to assume equivalent fallback filters on `GET /images`.

The API documents describe shipped versions, but an installed deployment can differ. Its authenticated `GET /v2/openapi.json` is authoritative for the operations, parameters, and response shapes that are actually available.

## Resolution

Keep the public locator modes explicit and route each one independently:

1. For `image_reference="registry.example.com/team/app:1.0"`, call `GET /v2/images?full_tag=registry.example.com%2Fteam%2Fapp%3A1.0`. Require an exact local tag match and resolve it to the corresponding digest before any digest-keyed call.
2. For `image_registry="registry.example.com"` plus `image_repository="team/app"`, call `GET /v2/summaries/image-tags?registry=registry.example.com&repository=team%2Fapp`. Walk the bounded `page`/`limit` response, require the returned `full_tag` to match both components exactly, and select the newest digest-bearing row with a valid `analyzed_at`.
3. Treat a missing, invalid, or tied newest analysis timestamp as an error instead of guessing.
4. Translate public `anchore_list_images.fulltag` to wire `full_tag`. Do not include `registry`, `repository`, or `repo` in the `/images` fallback allowlist; accept them only if the deployment OpenAPI explicitly advertises them for that operation.
5. Continue using bounded retry with backoff for the idempotent lookup GETs, and never log full backend bodies or credentials.

## Verification

- Exact-reference tests assert `/v2/images?full_tag=...`, reject `fulltag` on the wire, and require exact tag matching.
- Registry/repository tests assert `/v2/summaries/image-tags` with both component filters, bounded `items`/`total_rows` pagination, exact component matching, and newest selection using valid string or numeric `analyzed_at` values.
- List-image tests assert that public `fulltag` becomes `full_tag` and that registry/repository keys are absent from the static `/images` fallback allowlist.
- Run `pnpm run check` and `git diff --check` before committing.
- For a live deployment, inspect authenticated `GET https://anchore.example.com/v2/openapi.json` and confirm both operations and their query parameters before troubleshooting response data.

## Related

- [Anchore API research notes](../../research/anchore-api-notes.md)
- [Image registry and repository lookup design](../../superpowers/specs/2026-07-07-image-registry-repository-lookup-design.md)

## References

- [Current Anchore API specification](https://docs.anchore.com/current/docs/api/specs/anchore_api_swagger.yaml)
- [Anchore Enterprise 5.8 v2 API specification](https://docs.anchore.com/5.8/docs/api/v2/specs/anchore_api_swagger.yaml)
- Deployment `GET /v2/openapi.json` — authoritative for the installed deployment
