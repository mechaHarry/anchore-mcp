---
date: 2026-05-04
topic: policy-blocking-vulnerabilities
status: approved-design
---

# Policy Blocking Vulnerabilities Tool Design

## Purpose

Add a focused MCP tool, `anchore_policy_blocking_vulnerabilities`, for downstream agents that need one answer:

> For this image, which vulnerability remediations would cause the Anchore policy result to change from red to green?

The tool is not a broad vulnerability report, remediation handoff, SBOM lookup, or policy dump. It returns only compact vulnerability evidence that is provably tied to vulnerability-remediable policy blockers.

## Tool Contract

Inputs:

- `image_digest?: string`
- `image_reference?: string`
- `image_repository?: string`
- `tag?: string`
- `base_digest?: string`

Exactly one image locator is required:

- `image_digest` uses the supplied digest directly.
- `image_reference` is a fully qualified image reference such as `registry/repo:tag`.
- `image_repository` is a qualified repository/name without a tag, such as `registry/repo` or `registry/namespace/repo`; the tool selects the newest analyzed image across matching records.

`tag` and `base_digest` are passed only to Anchore `/check` as policy-evaluation context. They never replace the digest path key and are not inferred from unrelated inputs.

## Image Selection

The selector chooses one image before policy and vulnerability calls:

- For `image_digest`, use the digest directly.
- For `image_reference`, list images by `fulltag` where supported, then select the newest analyzed image if multiple digests match.
- For `image_repository`, list or scan bounded image records using allowlisted query parameters where possible, then select the newest analyzed image whose repository/name matches.

Newest image selection requires reliable timestamp metadata from Anchore image records. If timestamps are missing, unparsable, or tied across multiple digests, the tool returns an MCP error rather than guessing.

## Data Flow

1. Validate that exactly one locator is present.
2. Resolve/select a single image digest.
3. Call `GET /images/{digest}/check` with optional `tag` and `base_digest`.
4. If the policy is already green/pass, return success with `policyRemediationStatus: "already_green"` and `blockingVulnerabilities: []`.
5. If the policy is red/fail, call `GET /images/{digest}/vuln/all`.
6. Extract vulnerability-caused blocking policy findings from the policy payload.
7. Join policy blockers to vulnerability records only on strong evidence.
8. Return compact records for the joined vulnerabilities only.

## Proof Boundary

The tool must not infer causality from weak evidence.

Allowed joins:

- Exact vulnerability or CVE id match.
- Exact package identity match when the policy finding clearly identifies the vulnerable package and version.

Disallowed joins:

- Fuzzy text matching.
- Severity-only matching.
- Returning all high or critical vulnerabilities.
- Returning unrelated policy failures.

If the policy is red but the tool cannot prove which vulnerabilities would make it green, return an MCP error with `policyRemediationStatus: "red_policy_without_proven_vulnerability_fix"`.

## Output Shape

Successful tool results use the existing R8/R14 wrapper. The `anchore` payload is:

```json
{
  "reportVersion": "1.0.0",
  "policyRemediationStatus": "blocking_vulnerabilities_found",
  "selectedImage": {
    "digest": "sha256:...",
    "reference": "registry/repo:tag",
    "repository": "registry/repo",
    "analysisTimestamp": "..."
  },
  "blockingVulnerabilities": [
    {
      "id": "CVE-2026-1234",
      "severity": "critical",
      "packageName": "openssl",
      "packageVersion": "1.0.1",
      "packageType": "deb",
      "fixedVersion": "1.0.2",
      "imageLocations": [
        {
          "path": "/usr/lib/x86_64-linux-gnu/libssl.so.1.0.1",
          "kind": "file",
          "source": "vulnerability"
        }
      ],
      "policy": {
        "gate": "vulnerabilities",
        "trigger": "package",
        "reason": "..."
      },
      "evidence": {
        "matchedBy": ["vulnerabilityId"],
        "policyFindingRef": "stable best-effort identifier"
      }
    }
  ]
}
```

`selectedImage.digest` is always present. `reference`, `repository`, and `analysisTimestamp` are present when known from the selected image record or the caller input.

`imageLocations` is optional. It contains container/image file or directory paths only when Anchore vulnerability or policy evidence explicitly provides them. The tool does not fetch SBOM data or infer paths from package names in the first version.

## Error Semantics

Return MCP errors for:

- Missing, multiple, or malformed locators.
- No matching image.
- Multiple candidate images when newest selection cannot be proven.
- Missing or ambiguous timestamp metadata needed for newest selection.
- Policy check request failure.
- Vulnerability request failure after red policy.
- Red policy with no provable vulnerability-remediable blockers.

Green policy is not an error. It returns success with `policyRemediationStatus: "already_green"` and an empty `blockingVulnerabilities` list.

## Implementation Boundaries

Add focused modules:

- `src/tools/policy-blocking-vulnerabilities.ts`: tool runner and result assembly.
- `src/anchore/image-selection.ts`: digest, exact reference, and repository newest-image selection.
- `src/anchore/policy-blocker-extract.ts`: pure extraction of vulnerability-caused blocking policy findings.
- `src/anchore/vulnerability-records.ts`: pure vulnerability normalization and compact record construction.

Do not change `anchore_remediation_handoff` in this feature. Shared resolver/list/client helpers may be reused, but this tool owns a narrower schema and stricter error semantics.

No SBOM lookup is included in the first version.

## Tests

Required tests:

- Exact digest path works.
- Exact tag path resolves and selects the newest analyzed image.
- Repository path selects the newest analyzed image.
- Already-green policy returns success with an empty list.
- Red policy with exact CVE match returns one compact vulnerability.
- Red policy with exact package identity match returns a compact vulnerability.
- Anchore-provided file or directory paths are included as `imageLocations`.
- Red policy with unrelated or non-vulnerability findings returns an MCP error.
- Red policy with fuzzy-looking but unprovable matches returns an MCP error.
- Timestamp absence or ties return an MCP error.
- No token, authorization header, or full raw response body is written to stderr.

## Non-Goals

- No vulnerability prioritization outside policy blockers.
- No remediation execution.
- No image upload or scan trigger.
- No source repository routing.
- No SBOM-derived path inference in the first version.
- No broad policy report or raw Anchore dump.
