import { describe, expect, it } from "vitest";
import { imageFullTagQueryKey, imageTagSummariesPath } from "./api-paths.js";

describe("imageTagSummariesPath", () => {
  it.each(["v1", "v2"] as const)("builds the %s image-tag summary path", (version) => {
    const query = new URLSearchParams({ registry: "registry.example.com" });
    expect(imageTagSummariesPath(version, query)).toBe(
      `/${version}/summaries/image-tags?registry=registry.example.com`,
    );
  });
});

describe("imageFullTagQueryKey", () => {
  it.each([
    ["v1", "fulltag"],
    ["v2", "full_tag"],
  ] as const)("uses %s's %s query key", (version, expected) => {
    expect(imageFullTagQueryKey(version)).toBe(expected);
  });
});
