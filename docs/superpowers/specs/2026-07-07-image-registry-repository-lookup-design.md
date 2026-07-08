# Image registry and repository lookup design

## Goal

Replace the ambiguous combined `image_repository` lookup input with Anchore-aligned
image identifier components. This is an intentional breaking API change.

## Public tool contract

`anchore_policy_blocking_vulnerabilities` accepts exactly one image locator mode:

- `image_digest`: the analyzed image digest.
- `image_reference`: a fully qualified tagged reference in the form
  `registry/repository:tag`; it selects that exact analyzed tag.
- `image_registry` and `image_repository`: required together; they select the
  newest analyzed image in that repository across tags.

The prior combined `image_repository` value (`registry/repository`) is removed.
There is no compatibility alias because the repository owner chose a breaking
schema cleanup.

Examples:

```json
{ "image_reference": "docker.io/library/nginx:1.27" }
```

```json
{
  "image_registry": "docker.io",
  "image_repository": "library/nginx"
}
```

## Selection behavior

For the component locator, the MCP validates both non-empty strings, rejects
control characters and overlong values, and rejects all mixed or incomplete
locator combinations. It requests
the verified `GET /v2/summaries/image-tags?registry=...&repository=...` route
directly for v2, walks bounded `items`/`total_rows` pages, and considers only
rows whose `full_tag` matches both requested components exactly. V1 is
capability-gated: the MCP fetches `/v1/openapi.json` and calls
`/v1/summaries/image-tags` only when a prefixed `/v1/summaries/image-tags` or
unprefixed `/summaries/image-tags` `GET` operation directly declares both
`registry` and `repository` query parameters. Missing routes, indirect `$ref`
parameters, OpenAPI failures, and redirects all produce the same static
unsupported error without calling the v1 summary route.

This policy tool selects the newest digest-bearing row with a reliable analysis
timestamp. Every exact matching digest-bearing candidate must have such a
timestamp; one missing, invalid, or untrusted timestamp makes newest selection
fail closed because the MCP cannot prove which digest is newest. Matching
digestless rows cannot be selected and may be ignored. A tie at the newest
timestamp across digests is also an error rather than a guess.

Exact `image_reference` selection remains a separate operation:
`GET /v2/images?full_tag=registry/repository:tag`; legacy v1 uses
`GET /v1/images?fulltag=registry/repository:tag`. The MCP requires an exact
local tag match before using the resolved digest and applies the same
digest-bearing timestamp trust rule because this policy tool selects the newest
exact match.
The public `anchore_list_images.fulltag` convenience input is translated to the
version-specific wire key: `full_tag` for v2 and `fulltag` for v1.

Other digest-keyed tools use the shared `image_reference` resolver. That resolver
requires bounded exact local reference evidence, returns explicit
`enumeration_incomplete` when evidence cannot be fully inspected, and uses 0/1/N
digest cardinality. It does not select newest and does not use timestamps.

The MCP does not assume that `registry`, `repository`, or `repo` filter
`GET /v2/images`. Such keys are accepted there only if the deployment’s
`/v2/openapi.json` advertises them for that operation. That deployment schema is
authoritative.

The response keeps `selectedImage.repository` as the human-friendly qualified
`registry/repository` value because it is output evidence, not a tool input.

## Error handling and safety

Invalid combinations produce a stable, sanitized selection error; raw backend
data and user input are not written to stderr. The existing GET retry/backoff,
pagination bounds, ambiguity detection, and safe error mapping remain unchanged.
OpenAPI capability retrieval stays on the configured origin, bounds the response,
and does not follow redirects.

## Tests and documentation

Tests cover direct v2 summary routing, v1 capability gating for prefixed and
unprefixed path keys, direct query parameters, redirect/fetch failures, exact
`full_tag` matching, reliable analysis-timestamp parsing, bounded pagination,
fail-closed digest-bearing timestamp failures versus ignored digestless rows,
incomplete and mixed component pairs, shared-resolver exact evidence and
incomplete outcomes, version-specific full-tag query keys, and safe error
redaction. README and tool-schema descriptions distinguish an exact tagged
`image_reference` from the registry/repository lookup pair.
