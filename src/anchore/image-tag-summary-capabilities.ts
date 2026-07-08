import type { ResolvedAnchoreConnection } from "../config/connection.js";
import type { AnchoreClientOptions } from "./client.js";
import { fetchOpenApiDocument } from "./openapi-fetch.js";

const V1_IMAGE_TAG_SUMMARY_PATHS = [
  "/v1/summaries/image-tags",
  "/summaries/image-tags",
] as const;

function directQueryParameterNames(operation: unknown): Set<string> {
  const names = new Set<string>();
  if (operation === null || typeof operation !== "object") {
    return names;
  }
  const parameters = (operation as Record<string, unknown>).parameters;
  if (!Array.isArray(parameters)) {
    return names;
  }
  for (const parameter of parameters) {
    if (parameter === null || typeof parameter !== "object") {
      continue;
    }
    const candidate = parameter as Record<string, unknown>;
    if ("$ref" in candidate) {
      continue;
    }
    if (candidate.in === "query" && typeof candidate.name === "string") {
      names.add(candidate.name);
    }
  }
  return names;
}

export function openApiAdvertisesV1ImageTagSummaryFilters(doc: unknown): boolean {
  if (doc === null || typeof doc !== "object") {
    return false;
  }
  const paths = (doc as Record<string, unknown>).paths;
  if (paths === null || typeof paths !== "object") {
    return false;
  }
  for (const path of V1_IMAGE_TAG_SUMMARY_PATHS) {
    const pathItem = (paths as Record<string, unknown>)[path];
    if (pathItem === null || typeof pathItem !== "object") {
      continue;
    }
    const names = directQueryParameterNames(
      (pathItem as Record<string, unknown>).get,
    );
    if (names.has("registry") && names.has("repository")) {
      return true;
    }
  }
  return false;
}

export async function v1ImageTagSummaryFiltersAdvertised(
  connection: ResolvedAnchoreConnection,
  options?: AnchoreClientOptions,
): Promise<boolean> {
  try {
    const doc = await fetchOpenApiDocument(connection, options);
    return openApiAdvertisesV1ImageTagSummaryFilters(doc);
  } catch {
    return false;
  }
}
