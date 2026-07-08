import { describe, expect, it } from "vitest";
import { validateFullImageReference } from "./image-records.js";

describe("validateFullImageReference", () => {
  it("rejects a registry port when no image tag follows the repository", () => {
    expect(validateFullImageReference("registry.example.com:5000/team/app")).toEqual({
      ok: false,
      message: "image_reference must include a tag (registry/repo:tag).",
    });
  });

  it("accepts a registry port when a non-empty image tag follows the repository", () => {
    expect(
      validateFullImageReference("registry.example.com:5000/team/app:release"),
    ).toEqual({ ok: true });
  });

  it("rejects an empty tag suffix", () => {
    expect(validateFullImageReference("registry.example.com/team/app:")).toEqual({
      ok: false,
      message: "image_reference must include a tag (registry/repo:tag).",
    });
  });
});
