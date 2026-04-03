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

- `pnpm test` — URL expectations in `src/tools/sbom.test.ts` assert `.../sboms/native-json` (etc.).
- Live check: `GET https://<host>/v2/openapi.json` and search for `sboms` under `images`.

## References

- Deployment **`GET /v2/openapi.json`** (source of truth for exact paths)
