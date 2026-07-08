import { describe, expect, it } from "vitest";
import { imageTagSummariesPath } from "./api-paths.js";

describe("imageTagSummariesPath", () => {
  it.each(["v1", "v2"] as const)("builds the %s image-tag summary path", (version) => {
    const query = new URLSearchParams({ registry: "registry.example.com" });
    expect(imageTagSummariesPath(version, query)).toBe(
      `/${version}/summaries/image-tags?registry=registry.example.com`,
    );
  });
});
