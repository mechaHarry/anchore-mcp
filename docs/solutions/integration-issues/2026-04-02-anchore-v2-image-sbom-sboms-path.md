---
module: anchore-mcp
date: 2026-04-02
problem_type: integration_issue
component: tooling
severity: medium
symptoms:
  - HTTP 400 from Anchore Enterprise when fetching image SBOM via REST
  - MCP anchore_image_sbom tool appeared broken against a live deployment
root_cause: wrong_api
resolution_type: code_fix
tags:
  - anchore-enterprise
  - api-v2
  - sbom
  - rest-path
---

# Anchore Enterprise v2 image SBOM: use `sboms`, not `sbom`

## Context

The MCP server calls `GET` on the Anchore API to retrieve SBOM JSON for an image digest (`anchore_image_sbom` tool).

## Root cause

Anchore Enterprise **v2** OpenAPI defines image SBOM routes with a plural path segment: **`/v2/images/{image_digest}/sboms/{format}`**. Using **`/sbom/`** (singular) does not match the registered route and can return **HTTP 400** (Bad Request), which is easy to misread as a client bug or bad digest.

Source-repository SBOM endpoints documented elsewhere may still use **`/v2/sources/.../sbom/...`** (singular). Image and source paths are not the same.

## Resolution

- Implement **`imageSbomPath`** with **`/sboms/`** for **`ANCHORE_API_VERSION=v2`** (default).
- Keep v1 as best-effort **`/v1/images/.../sbom/...`** only if legacy deployments require it; confirm on their OpenAPI.
- Document the pitfall in [docs/research/anchore-api-notes.md](../../research/anchore-api-notes.md) and in AGENTS.md “What we learned”.

## Verification

- `uv run pytest tests/unit/tools/test_image_sbom.py -q` — route expectations assert `.../sboms/native-json` (and the SPDX/CycloneDX variants).
- Live check: `GET https://<host>/v2/openapi.json` and search for `sboms` under `images`.

## Related

- If the path uses **`/sboms/`** but requests still fail with **400**, confirm the **`{image_digest}`** segment is a real analyzed digest (`sha256:…`), not a registry tag — see [Anchore v2 digest vs tag](../best-practices/2026-04-03-anchore-v2-digest-vs-tag-image-apis.md).

## References

- Deployment **`GET /v2/openapi.json`** (source of truth for exact paths)
