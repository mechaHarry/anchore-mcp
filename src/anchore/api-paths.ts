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
