/** Anchore REST path version segment (`/v1/...` vs `/v2/...`). */
export type AnchoreApiVersion = "v1" | "v2";

export function imagesListPath(
  version: AnchoreApiVersion,
  query: URLSearchParams,
): string {
  const base = version === "v1" ? "/v1/images" : "/v2/images";
  const qs = query.toString();
  return qs ? `${base}?${qs}` : base;
}

/** Image tag summaries used for registry/repository selection. */
export function imageTagSummariesPath(
  version: AnchoreApiVersion,
  query: URLSearchParams,
): string {
  const base = `/${version}/summaries/image-tags`;
  const qs = query.toString();
  return qs ? `${base}?${qs}` : base;
}

/**
 * V1: GET /v1/images/{digest}/vulnerabilities
 * V2: GET /v2/images/{digest}/vuln/all — see deployment `/v2/openapi.json`
 */
export function imageVulnerabilitiesPath(
  version: AnchoreApiVersion,
  digest: string,
): string {
  const enc = encodeURIComponent(digest);
  if (version === "v1") {
    return `/v1/images/${enc}/vulnerabilities`;
  }
  return `/v2/images/${enc}/vuln/all`;
}

/** Syft / SPDX / CycloneDX SBOM sub-path segments (see deployment `/v2/openapi.json`). */
export type ImageSbomFormatPath =
  | "native-json"
  | "spdx-json"
  | "cyclonedx-json";

/**
 * V2: `GET /v2/images/{digest}/sboms/{format}` (plural `sboms` per Enterprise OpenAPI).
 * V1: best-effort `/v1/images/.../sbom/...`; confirm on legacy deployments.
 */
export function imageSbomPath(
  version: AnchoreApiVersion,
  digest: string,
  format: ImageSbomFormatPath,
): string {
  const enc = encodeURIComponent(digest);
  if (version === "v1") {
    return `/v1/images/${enc}/sbom/${format}`;
  }
  return `/v2/images/${enc}/sboms/${format}`;
}

/** Single image record (build-summary style metadata). */
export function imageByDigestPath(
  version: AnchoreApiVersion,
  digest: string,
): string {
  const enc = encodeURIComponent(digest);
  if (version === "v1") {
    return `/v1/images/${enc}`;
  }
  return `/v2/images/${enc}`;
}

/**
 * Policy evaluation for an image digest.
 * Often used with `?tag=registry/repo:tag` — see Anchore docs for your version.
 */
export function imagePolicyCheckPath(
  version: AnchoreApiVersion,
  digest: string,
  query: URLSearchParams,
): string {
  const enc = encodeURIComponent(digest);
  const base =
    version === "v1" ? `/v1/images/${enc}/check` : `/v2/images/${enc}/check`;
  const qs = query.toString();
  return qs ? `${base}?${qs}` : base;
}
