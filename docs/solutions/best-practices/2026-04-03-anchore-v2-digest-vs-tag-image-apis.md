---
title: Anchore v2 image APIs — digest in path vs tag query
date: 2026-04-03
module: anchore-mcp
problem_type: best_practice
component: tooling
severity: low
applies_when:
  - Building or debugging clients that call Anchore Enterprise v2 image routes (MCP tools, scripts, or integrations)
  - Interpreting HTTP 400/404 when the caller passes a registry tag where a digest is required (or vice versa)
tags:
  - anchore-enterprise
  - api-v2
  - image-digest
  - image-tag
  - rest
---

# Anchore v2 image APIs — digest in path vs tag query

## Context

Anchore’s v2 REST API exposes most **per-image** operations under paths like:

`GET /v2/images/{image_digest}/…`

Assistants and operators often have both a **digest** (`sha256:…`) and a **registry tag** (`registry/repo:tag`) at hand. It is easy to assume those identifiers are interchangeable in every call. They are not: **route shape and optional query parameters differ by endpoint**, which shows up as confusing **400 Bad Request** or **404** responses when the wrong identifier is placed in the path or omitted where required.

This guidance applies to **anchore-mcp** tools and to any direct use of the same Anchore routes.

## Guidance

1. **Treat `{image_digest}` in the path as the analyzed image key Anchore stored** — almost always a **`sha256:…`** digest string. Do not put a bare **tag** (e.g. `docker.io/library/nginx:latest`) into that path segment unless your deployment’s OpenAPI explicitly documents that form (most do not).

2. **SBOM and other “artifact” reads** (`…/sboms/…`, `…/vuln/…`, `GET /v2/images/{digest}`) are **digest-centric**: the MCP **`anchore_image_sbom`** tool only maps **`image_digest`** into the path. There is **no** parallel `tag=` parameter on those image SBOM routes in the usual v2 contract. If SBOM “works with hash but not tag,” that matches the API: **tags are not first-class inputs for that operation**.

3. **Policy evaluation** (`GET /v2/images/{digest}/check`) still uses the **digest in the path**, but Anchore often documents **optional query parameters** such as **`tag`** and **`base_digest`** for evaluation context. Some deployments or policies behave poorly when the digest is valid but **tag context** is missing or wrong — symptoms can look like “policy works when I pass the tag.” That does **not** mean other routes accept tag instead of digest; it means **`/check` has extra query semantics**.

4. **Composite tools** (e.g. remediation handoff) that call **detail + vulnerabilities + optional policy** fail if **any** of the required digest-based calls fail. If only policy is sensitive to `tag`, partial success is not exposed — fix inputs per endpoint.

5. **Source of truth:** `GET https://<anchore-host>/v2/openapi.json` for your deployment — parameter names and required vs optional fields drift by version.

## Why This Matters

Mixing up digest and tag produces **valid-looking URLs that are semantically wrong** (e.g. encoding `repo:tag` as a path segment). That wastes triage time and looks like “MCP bugs” or “Anchore bugs” when the client is simply not matching the OpenAPI contract.

## When to Apply

- Implementing or extending **image-scoped** Anchore tools.
- Debugging **400** responses on image routes after copy-pasting a **tag** into a field labeled digest.
- Explaining why **SBOM** and **policy** can appear to have **different** “hash vs tag” behavior.

## Examples

**Prefer (digest in path):**

```http
GET /v2/images/sha256%3Aabcdef…/sboms/native-json
GET /v2/images/sha256%3Aabcdef…/vuln/all
```

**Policy with optional tag context (query — does not replace path digest):**

```http
GET /v2/images/sha256%3Aabcdef…/check?tag=docker.io/library/nginx%3Alatest
```

**Avoid:**

- Using `docker.io/library/nginx:latest` as the sole `{image_digest}` path segment for SBOM or vuln routes unless OpenAPI says so.
- Assuming “works with tag” for one endpoint implies all image endpoints accept tags the same way.

## Related

- Same integration area, **different** issue (path spelling): [docs/solutions/integration-issues/2026-04-02-anchore-v2-image-sbom-sboms-path.md](../integration-issues/2026-04-02-anchore-v2-image-sbom-sboms-path.md)
- Research notes: [docs/research/anchore-api-notes.md](../../research/anchore-api-notes.md)
- Remediation handoff schema: [docs/remediation-handoff-schema.md](../../remediation-handoff-schema.md)
