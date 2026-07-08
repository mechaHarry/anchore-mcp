import { describe, expect, it } from "vitest";
import {
  FALLBACK_LIST_IMAGES_QUERY_KEYS,
  extractListImagesQueryParameterNames,
  getFallbackListImagesQueryKeys,
  mergeListImagesQueryParams,
} from "./openapi-list-images-params.js";

describe("extractListImagesQueryParameterNames", () => {
  it("collects query parameter names from OpenAPI path get", () => {
    const doc = {
      paths: {
        "/v2/images": {
          get: {
            parameters: [
              { name: "fulltag", in: "query" },
              { name: "body", in: "body" },
              { $ref: "#/components/parameters/X" },
              { name: "repo", in: "query" },
            ],
          },
        },
      },
    };
    expect(extractListImagesQueryParameterNames(doc, "/v2/images")).toEqual([
      "fulltag",
      "repo",
    ]);
  });
});

describe("mergeListImagesQueryParams", () => {
  it("uses only official conservative fallback filters", () => {
    expect(FALLBACK_LIST_IMAGES_QUERY_KEYS).toContain("full_tag");
    expect(FALLBACK_LIST_IMAGES_QUERY_KEYS).not.toContain("fulltag");
    expect(FALLBACK_LIST_IMAGES_QUERY_KEYS).not.toContain("registry");
    expect(FALLBACK_LIST_IMAGES_QUERY_KEYS).not.toContain("repository");
    expect(FALLBACK_LIST_IMAGES_QUERY_KEYS).not.toContain("repo");
  });

  it("merges allowlisted list_query keys", () => {
    const allow = new Set(["fulltag", "name", "limit"]);
    const { params, rejectedKeys } = mergeListImagesQueryParams(
      {
        list_query: { name: "x", limit: "10" },
      },
      allow,
      "v2",
    );
    expect(params.get("name")).toBe("x");
    expect(params.get("limit")).toBe("10");
    expect(rejectedKeys).toEqual([]);
  });

  it("rejects unknown keys", () => {
    const allow = new Set(["name"]);
    const { rejectedKeys } = mergeListImagesQueryParams(
      {
        list_query: { not_allowed: "1" },
      },
      allow,
      "v2",
    );
    expect(rejectedKeys).toContain("not_allowed");
  });

  it("maps explicit fulltag input to full_tag and prefers it over list_query", () => {
    const allow = new Set(["full_tag", "fulltag"]);
    const { params } = mergeListImagesQueryParams(
      {
        fulltag: "docker.io/a:b",
        list_query: {
          full_tag: "docker.io/c:d",
          fulltag: "docker.io/legacy:e",
        },
      },
      allow,
      "v2",
    );
    expect(params.get("full_tag")).toBe("docker.io/a:b");
    expect(params.has("fulltag")).toBe(false);
  });

  it.each([
    ["v1", "fulltag", "full_tag"],
    ["v2", "full_tag", "fulltag"],
  ] as const)("maps public fulltag to the %s wire key", (version, expected, absent) => {
    const allow = new Set(["fulltag", "full_tag"]);
    const { params } = mergeListImagesQueryParams(
      {
        fulltag: "registry.example.com/team/app:1",
        list_query: {
          fulltag: "registry.example.com/legacy/app:1",
          full_tag: "registry.example.com/custom/app:1",
        },
      },
      allow,
      version,
    );

    expect(params.get(expected)).toBe("registry.example.com/team/app:1");
    expect(params.has(absent)).toBe(false);
  });
});

describe("getFallbackListImagesQueryKeys", () => {
  it.each([
    ["v1", "fulltag", "full_tag"],
    ["v2", "full_tag", "fulltag"],
  ] as const)("trusts only the %s full-tag fallback key", (version, expected, absent) => {
    const keys = getFallbackListImagesQueryKeys(version);
    expect(keys).toContain(expected);
    expect(keys).not.toContain(absent);
  });
});
