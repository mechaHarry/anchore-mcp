---
status: completed
completed: 2026-07-08
implementation_commits:
  - 7ed2e34
  - e7a35be
  - d6c639f
  - 1b7efb4
  - 6702c39
documentation_commits:
  - 68d5289
---

# Image Registry and Repository Lookup Implementation Plan

> **Completed historical record:** Do not execute this plan again. The checked
> steps preserve the original test-first audit trail; the implementation and
> trust-boundary follow-ups are recorded in the commits above.

**Goal:** Replace the ambiguous combined repository locator with the required `image_registry` and `image_repository` pair for policy-blocking vulnerability lookup.

**Architecture:** Keep digest and exact tagged-reference selection unchanged at the MCP boundary. Resolve exact references through `GET /v2/images?full_tag=...` or legacy `GET /v1/images?fulltag=...`; resolve a registry/repository pair through the wire-faithful `GET /v2/summaries/image-tags?registry=...&repository=...`, then use the selected digest for downstream image routes. Newest selection fails closed if any exact matching digest-bearing candidate lacks a reliable analysis timestamp; matching digestless rows may be ignored. Make the MCP schema, safe error provenance, examples, and historical design record describe the breaking contract consistently.

**Tech Stack:** TypeScript, Zod, MCP SDK, Vitest, ESLint, pnpm.

---

## File structure

- Modify `src/anchore/image-selection.ts`: locator type, component validation, row extraction, exact matching, and list-query construction.
- Modify `src/anchore/image-selection.test.ts`: selection behavior and invalid-locator tests.
- Modify `src/tools/policy-blocking-vulnerabilities.ts`: stable error-message allowlist for the new components.
- Modify `src/tools/policy-blocking-vulnerabilities.test.ts`: safe error mapping and selected-reference policy-query coverage.
- Modify `src/mcp/server.ts`: public MCP tool schema and descriptions.
- Modify `README.md`, `examples/codex-agent-setup/README.md`, `docs/research/anchore-api-notes.md`, `docs/superpowers/specs/2026-07-07-image-registry-repository-lookup-design.md`, and `docs/superpowers/specs/2026-05-04-policy-blocking-vulnerabilities-design.md`: consumer-facing contract, route research, and design corrections.
- Add `docs/solutions/integration-issues/2026-07-08-anchore-v2-image-lookup-routes.md`: durable integration learning for identifier-specific lookup routes.
- Modify `AGENTS.md`: short operational pointer to the fossilized lookup-route learning.

### Task 1: Make repository selection component-aware

**Files:**
- Modify: `src/anchore/image-selection.ts:11-410`
- Test: `src/anchore/image-selection.test.ts:135-350`

- [x] **Step 1: Write failing exact-component selection tests**

  Replace the combined-string repository test with a test that invokes:

  ```ts
  const result = await selectImageForPolicyBlockingReport(
    {
      image_registry: "registry.example.com",
      image_repository: "team/app",
    },
    testConn(),
    { fetch: fetchMock },
  );
  ```

  Use image rows whose `image_detail` items contain separate `registry`, `repo`, and `tag` fields. Include a newer row with the same repo but a different registry, and assert it is excluded. Assert the selected output contains `repository: "registry.example.com/team/app"`, and the request URL contains both `registry=registry.example.com` and `repository=team%2Fapp`.

- [x] **Step 2: Run the focused test to verify it fails**

  Run: `pnpm test src/anchore/image-selection.test.ts`

  Expected: FAIL because `image_registry` is not a recognized locator and the existing combined repository matching cannot satisfy the requested component pair.

- [x] **Step 3: Implement the minimal component locator and exact matching**

  Replace the locator and selection shape with the following contract:

  ```ts
  export type PolicyBlockingImageLocator = {
    image_digest?: string;
    image_reference?: string;
    image_registry?: string;
    image_repository?: string;
  };

  type RepositoryLocator = {
    registry: string;
    repository: string;
  };
  ```

  Normalize locators so only `image_digest`, `image_reference`, or a complete
  `image_registry` + `image_repository` pair is accepted. Reject an incomplete
  pair and any mixture with a digest or reference. Validate each component with
  the existing empty, length (1024), and control-character protections; reject a
  registry containing `/`, a repository beginning/ending with `/`, and a
  repository containing a tag separator after its final `/`.

  Extract registry/repository pairs from nested `image_detail` metadata and from
  full tag/reference fields. In `selectByRepository`, set separate `registry`
  and `repository` request parameters, require an exact component-pair match,
  and compose `${registry}/${repository}` solely for `SelectedImage.repository`.
  Fail closed if any exact matching digest-bearing candidate lacks a reliable
  analysis timestamp; digestless rows cannot be selected and may be ignored.

- [x] **Step 4: Run the focused tests to verify they pass**

  Run: `pnpm test src/anchore/image-selection.test.ts`

  Expected: PASS, including unchanged digest/reference selection, timestamps,
  ambiguity, and pagination behavior.

- [x] **Step 5: Commit the selection refactor**

  ```bash
  git add src/anchore/image-selection.ts src/anchore/image-selection.test.ts
  git commit -S -m "feat: separate image registry and repository lookup"
  ```

### Task 2: Enforce and safely report the public locator contract

**Files:**
- Modify: `src/tools/policy-blocking-vulnerabilities.ts:79-109`
- Modify: `src/tools/policy-blocking-vulnerabilities.test.ts:350-455`
- Modify: `src/mcp/server.ts:153-185`
- Test: `src/anchore/image-selection.test.ts:315-350`
- Test: `src/mcp/server.test.ts:25-45`

- [x] **Step 1: Write failing validation and safe-error tests**

  Add table-driven `selectImageForPolicyBlockingReport` cases for:

  ```ts
  { image_registry: "registry.example.com" }
  { image_repository: "team/app" }
  { image_digest: "sha256:a", image_registry: "registry.example.com", image_repository: "team/app" }
  { image_reference: "registry.example.com/team/app:latest", image_registry: "registry.example.com", image_repository: "team/app" }
  ```

  Each must return `image_selection_error` without making an HTTP request. Update
  the unsafe-message sanitization table to include an error beginning with
  `image_registry` and one beginning with `image_repository`, then assert that
  `RAW_BODY_MARKER` never reaches either tool JSON or stderr.

- [x] **Step 2: Run the focused tests to verify they fail**

  Run: `pnpm test src/anchore/image-selection.test.ts src/tools/policy-blocking-vulnerabilities.test.ts`

  Expected: FAIL because incomplete-pair errors and the new safe message set do
  not yet exist.

- [x] **Step 3: Update the MCP schema and safe error mapping**

  In `anchore_policy_blocking_vulnerabilities`, replace the combined-field
  description with:

  ```ts
  image_registry: z.string().optional().describe("Anchore registry component; requires image_repository."),
  image_repository: z.string().optional().describe("Anchore repository component without registry or tag; requires image_registry."),
  ```

  Change the tool description and selection error text to say that callers pass
  exactly one of `image_digest`, `image_reference`, or the
  `image_registry` + `image_repository` pair. Allowlist every exact validation
  message emitted by the new component validators, while preserving the generic
  fallback for unexpected backend errors.

- [x] **Step 4: Run focused tests to verify they pass**

  Run: `pnpm test src/anchore/image-selection.test.ts src/tools/policy-blocking-vulnerabilities.test.ts src/mcp/server.test.ts`

  Expected: PASS; no test output contains the raw marker.

- [x] **Step 5: Commit the public-contract enforcement**

  ```bash
  git add src/anchore/image-selection.ts src/anchore/image-selection.test.ts src/tools/policy-blocking-vulnerabilities.ts src/tools/policy-blocking-vulnerabilities.test.ts src/mcp/server.ts src/mcp/server.test.ts
  git commit -S -m "feat: validate image lookup component pair"
  ```

### Task 3: Correct lookup routes to the versioned Anchore wire contract

**Files:**
- Modify: `src/anchore/api-paths.ts`
- Modify: `src/anchore/image-selection.ts`
- Modify: `src/anchore/resolve-image-reference.ts`
- Modify: `src/anchore/openapi-list-images-params.ts`
- Modify: corresponding `*.test.ts` files

- [x] **Step 1: Write failing route and pagination tests**

  Assert that repository selection uses `/v2/summaries/image-tags` with separate
  `registry` and `repository` query parameters and that exact references use
  `/v2/images?full_tag=...` or legacy `/v1/images?fulltag=...`. Cover `items`
  plus `total_rows` pagination, cap exhaustion, exact local tag matching,
  numeric epoch `analyzed_at`, fail-closed digest-bearing timestamp gaps, and
  ignored digestless rows.

- [x] **Step 2: Run focused tests to verify they fail**

  Run: `pnpm test src/anchore/image-selection.test.ts src/anchore/resolve-image-reference.test.ts src/anchore/openapi-list-images-params.test.ts`

  Expected: FAIL because repository selection still calls `/images` and v2
  exact-reference resolution still emits the wrong `fulltag` wire key.

- [x] **Step 3: Implement the wire-faithful routes**

  Add a versioned image-tag-summary path helper and a bounded page walker for
  the official `items`/`total_rows`, `page`, and `limit` contract. Preserve the
  explicit MCP component inputs, selector error provenance, exact local match,
  and output shape. Translate the public `fulltag` convenience input to
  version-specific wire keys: `full_tag` for v2 and `fulltag` for v1. Remove
  `registry`, `repository`, and `repo` from the `/images` fallback allowlist;
  deployment OpenAPI may still add advertised custom parameters. Require a
  reliable timestamp for every exact matching digest-bearing candidate, while
  allowing digestless rows to be ignored.

- [x] **Step 4: Run focused and full verification**

  Run: `pnpm test src/anchore/image-selection.test.ts src/anchore/resolve-image-reference.test.ts src/anchore/openapi-list-images-params.test.ts && pnpm run check`

  Expected: all focused tests and the full lint/typecheck/build/test gate pass.

- [x] **Step 5: Commit the route correction**

  ```bash
  git add src/anchore
  git commit -S -m "fix: use Anchore image lookup routes"
  ```

### Task 4: Update consumer documentation and validate the repository

**Files:**
- Modify: `README.md:61-68`
- Modify: `examples/codex-agent-setup/README.md:5-12,140-147`
- Modify: `docs/research/anchore-api-notes.md`
- Modify: `docs/superpowers/specs/2026-07-07-image-registry-repository-lookup-design.md`
- Modify: `docs/superpowers/specs/2026-05-04-policy-blocking-vulnerabilities-design.md:19-42`
- Add: `docs/solutions/integration-issues/2026-07-08-anchore-v2-image-lookup-routes.md`
- Modify: `AGENTS.md`

- [x] **Step 1: Update consumer examples and contract wording**

  Replace each combined `image_repository="registry/repository"` example with
  an explicit pair, for example:

  ```text
  image_registry="containers.example.com" and image_repository="psf/help-site"
  ```

  In the README locator list, retain `image_reference` as the exact
  `registry/repository:tag` choice and state that repository lookup requires the
  `image_registry` plus `image_repository` pair and selects the newest analyzed
  tag. Record that exact references use `/v2/images?full_tag=...`, component
  lookup uses `/v2/summaries/image-tags?registry=...&repository=...`, and
  `anchore_list_images.fulltag` is translated to `full_tag` on v2 while v1
  retains `fulltag`. Correct both design documents and API research so they do
  not imply registry or repository fallback filters on `/images`; the
  deployment `/v2/openapi.json` remains authoritative.

  Fossilize the verified route distinction in `docs/solutions/integration-issues/`
  with symptoms, root cause, resolution, verification, and references to the
  official current and 5.8 specifications. Add only a short operational pointer
  to `AGENTS.md`; do not duplicate the learning in `MEMORY.md`.

- [x] **Step 2: Run documentation reference scan**

  Run: `rg -n '/v2/images\?fulltag|/v1/images\?full_tag|image_repository="[^" ]*/|image_repository\s*\([^)]*registry/repo|registry.*repository.*(/v2/)?images|/images.*registry.*repository' README.md AGENTS.md examples docs`

  Expected: no current documentation presents `image_repository` as a combined
  registry/repository value, emits the wrong version’s full-tag key, or treats
  registry and repository as assumed `/images` filters. Historical text may
  name the former combined input only when explicitly describing it as removed
  or wrong.

- [x] **Step 3: Run the full quality gate**

  Run: `pnpm run check`

  Expected: exit 0 from lint, typecheck, build, and all Vitest suites.

- [x] **Step 4: Inspect the final change set**

  Run: `git diff --check && git status --short && git diff -- src/anchore/image-selection.ts src/mcp/server.ts src/tools/policy-blocking-vulnerabilities.ts README.md examples/codex-agent-setup/README.md`

  Expected: no whitespace errors; only intentional lookup-contract changes plus
  pre-existing unrelated working-tree files.

- [x] **Step 5: Commit documentation**

  ```bash
  git add AGENTS.md README.md examples/codex-agent-setup/README.md docs/research/anchore-api-notes.md docs/solutions/integration-issues/2026-07-08-anchore-v2-image-lookup-routes.md docs/superpowers/specs/2026-07-07-image-registry-repository-lookup-design.md docs/superpowers/specs/2026-05-04-policy-blocking-vulnerabilities-design.md docs/superpowers/plans/2026-07-07-image-registry-repository-lookup.md
  git commit -S -m "docs: clarify Anchore image lookup routes"
  ```
