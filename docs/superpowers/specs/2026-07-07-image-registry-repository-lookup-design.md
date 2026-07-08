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
locator combinations. It requests the Anchore image list with separate
`registry` and `repository` query parameters. It then only considers rows whose
separate registry and repository metadata match both requested components
exactly, selecting the newest row with a digest and reliable analysis timestamp.

The response keeps `selectedImage.repository` as the human-friendly qualified
`registry/repository` value because it is output evidence, not a tool input.

## Error handling and safety

Invalid combinations produce a stable, sanitized selection error; raw backend
data and user input are not written to stderr. The existing GET retry/backoff,
pagination bounds, ambiguity detection, and safe error mapping remain unchanged.

## Tests and documentation

Tests will cover the separate query parameters, exact nested v2 registry/repo
matching, newest-image selection, incomplete and mixed component pairs, and
safe error redaction. README and tool-schema descriptions will distinguish an
exact tagged `image_reference` from the registry/repository lookup pair.
