import { describe, expect, it } from "vitest";
import {
  extractListImagesQueryParameterNames,
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
  it("merges allowlisted list_query keys", () => {
    const allow = new Set(["fulltag", "name", "limit"]);
    const { params, rejectedKeys } = mergeListImagesQueryParams(
      {
        list_query: { name: "x", limit: "10" },
      },
      allow,
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
    );
    expect(rejectedKeys).toContain("not_allowed");
  });

  it("prefers explicit fulltag over list_query fulltag", () => {
    const allow = new Set(["fulltag"]);
    const { params } = mergeListImagesQueryParams(
      {
        fulltag: "docker.io/a:b",
        list_query: { fulltag: "docker.io/c:d" },
      },
      allow,
    );
    expect(params.get("fulltag")).toBe("docker.io/a:b");
  });
});
