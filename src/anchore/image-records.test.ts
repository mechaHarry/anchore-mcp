import { describe, expect, it } from "vitest";
import {
  fullImageReferencesFromRow,
  validateFullImageReference,
} from "./image-records.js";

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

describe("fullImageReferencesFromRow", () => {
  it("extracts valid top-level aliases and tags array entries", () => {
    expect(
      fullImageReferencesFromRow({
        full_tag: "registry.example.com/team/app:1",
        imageTag: "registry.example.com/team/app:2",
        tag: "latest",
        tags: ["registry.example.com/team/app:3", "not-qualified"],
      }),
    ).toEqual([
      "registry.example.com/team/app:1",
      "registry.example.com/team/app:2",
      "registry.example.com/team/app:3",
    ]);
  });

  it("extracts nested full tags and coherent registry repository tag shapes", () => {
    expect(
      fullImageReferencesFromRow({
        image_detail: [
          { fulltag: "registry.example.com/team/app:1" },
          {
            registry: "registry.example.com:5000",
            repo: "team/app",
            tag: "release",
          },
        ],
        imageDetail: {
          registry: "registry.example.com",
          repository: "team/other",
          tag: "2",
        },
      }),
    ).toEqual([
      "registry.example.com/team/app:1",
      "registry.example.com:5000/team/app:release",
      "registry.example.com/team/other:2",
    ]);
  });

  it("does not synthesize references across incompatible aliases", () => {
    expect(
      fullImageReferencesFromRow({
        image_detail: [
          {
            registry: "registry.example.com",
            imageRepository: "team/app",
            tag: "1",
          },
          {
            registry: "registry.example.com",
            repo: "team/one",
            repository: "team/two",
            tag: "1",
          },
        ],
      }),
    ).toEqual([]);
  });
});
