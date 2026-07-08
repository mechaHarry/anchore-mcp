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
`GET /v2/summaries/image-tags?registry=...&repository=...`, walks the bounded
`items`/`total_rows` pages, and considers only rows whose `full_tag` matches both
requested components exactly. It selects the newest digest-bearing row with a
valid `analyzed_at`; missing or tied newest timestamps are errors rather than
guessing.

Exact `image_reference` selection remains a separate operation:
`GET /v2/images?full_tag=registry/repository:tag`. The MCP requires an exact
local tag match before using the resolved digest. The public
`anchore_list_images.fulltag` convenience input is likewise translated to the
wire key `full_tag`.

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

## Tests and documentation

Tests cover the summary route and separate query parameters, exact `full_tag`
matching, valid `analyzed_at` newest-image selection, bounded pagination,
incomplete and mixed component pairs, `fulltag` to `full_tag` translation, and
safe error redaction. README and tool-schema descriptions distinguish an exact
tagged `image_reference` from the registry/repository lookup pair.
