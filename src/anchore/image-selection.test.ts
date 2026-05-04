import { describe, expect, it, vi } from "vitest";
import type { ResolvedAnchoreConnection } from "../config/connection.js";
import { selectImageForPolicyBlockingReport } from "./image-selection.js";

function testConn(): ResolvedAnchoreConnection {
  return {
    baseUrl: "https://anchore.example.com",
    username: "_api_key",
    password: "t",
    apiVersion: "v2",
  };
}

function okList(items: unknown[]): Response {
  return new Response(JSON.stringify({ items }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

describe("selectImageForPolicyBlockingReport", () => {
  it("uses a digest directly", async () => {
    const result = await selectImageForPolicyBlockingReport(
      { image_digest: "  sha256:direct  " },
      testConn(),
      { fetch: vi.fn() },
    );

    expect(result).toEqual({
      ok: true,
      selectedImage: { digest: "sha256:direct" },
    });
  });

  it("selects the newest analyzed digest for an exact reference", async () => {
    const requested = "docker.io/library/nginx:1.25";
    const fetchMock = vi.fn().mockResolvedValue(
      okList([
        {
          image_digest: "sha256:old",
          fulltag: requested,
          analyzed_at: "2026-04-01T00:00:00Z",
        },
        {
          image_digest: "sha256:new",
          fulltag: requested,
          analyzed_at: "2026-04-02T00:00:00Z",
        },
      ]),
    );

    const result = await selectImageForPolicyBlockingReport(
      { image_reference: requested },
      testConn(),
      { fetch: fetchMock },
    );

    expect(result).toEqual({
      ok: true,
      selectedImage: {
        digest: "sha256:new",
        reference: requested,
        repository: "docker.io/library/nginx",
        analysisTimestamp: "2026-04-02T00:00:00Z",
      },
    });
    expect(fetchMock.mock.calls[0][0]).toContain("fulltag=");
    expect(fetchMock.mock.calls[0][0]).toContain(encodeURIComponent(requested));
  });

  it("ignores rows with the same repository but a different tag for exact reference selection", async () => {
    const requested = "docker.io/library/nginx:1.25";
    const fetchMock = vi.fn().mockResolvedValue(
      okList([
        {
          image_digest: "sha256:requested",
          full_tag: requested,
          analyzedAt: "2026-04-02T00:00:00Z",
        },
        {
          image_digest: "sha256:other-tag",
          fulltag: "docker.io/library/nginx:latest",
          analyzedAt: "2026-04-03T00:00:00Z",
        },
      ]),
    );

    const result = await selectImageForPolicyBlockingReport(
      { image_reference: requested },
      testConn(),
      { fetch: fetchMock },
    );

    expect(result).toEqual({
      ok: true,
      selectedImage: {
        digest: "sha256:requested",
        reference: requested,
        repository: "docker.io/library/nginx",
        analysisTimestamp: "2026-04-02T00:00:00Z",
      },
    });
  });

  it("selects the newest matching repository across tags", async () => {
    const repository = "registry.example.com/team/app";
    const fetchMock = vi.fn().mockResolvedValue(
      okList([
        {
          imageDigest: "sha256:old",
          fulltag: "registry.example.com/team/app:1.0",
          analyzed_at: "2026-04-01T00:00:00Z",
        },
        {
          imageDigest: "sha256:new",
          imageTag: "registry.example.com/team/app:2.0",
          analyzed_at: "2026-04-03T00:00:00Z",
        },
        {
          imageDigest: "sha256:wrong-repo",
          fulltag: "registry.example.com/team/other:9.0",
          analyzed_at: "2026-04-04T00:00:00Z",
        },
      ]),
    );

    const result = await selectImageForPolicyBlockingReport(
      { image_repository: repository },
      testConn(),
      { fetch: fetchMock },
    );

    expect(result).toEqual({
      ok: true,
      selectedImage: {
        digest: "sha256:new",
        reference: "registry.example.com/team/app:2.0",
        repository,
        analysisTimestamp: "2026-04-03T00:00:00Z",
      },
    });
    expect(fetchMock.mock.calls[0][0]).toContain("repository=");
    expect(fetchMock.mock.calls[0][0]).toContain(encodeURIComponent(repository));
  });

  it("returns image_selection_error when the newest timestamp is tied across digests", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      okList([
        {
          image_digest: "sha256:a",
          repository: "registry.example.com/team/app",
          analyzed_at: "2026-04-02T00:00:00Z",
        },
        {
          image_digest: "sha256:b",
          repository: "registry.example.com/team/app",
          analyzed_at: "2026-04-02T00:00:00Z",
        },
      ]),
    );

    const result = await selectImageForPolicyBlockingReport(
      { image_repository: "registry.example.com/team/app" },
      testConn(),
      { fetch: fetchMock },
    );

    expect(result).toMatchObject({
      ok: false,
      status: "image_selection_error",
    });
  });

  it("returns image_selection_error when no matching row has a valid timestamp", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      okList([
        {
          image_digest: "sha256:a",
          fulltag: "registry.example.com/team/app:1.0",
          analyzed_at: "not-a-date",
        },
        {
          image_digest: "sha256:b",
          fulltag: "registry.example.com/team/app:2.0",
        },
      ]),
    );

    const result = await selectImageForPolicyBlockingReport(
      { image_repository: "registry.example.com/team/app" },
      testConn(),
      { fetch: fetchMock },
    );

    expect(result).toMatchObject({
      ok: false,
      status: "image_selection_error",
    });
  });

  it("requires exactly one locator", async () => {
    const connection = testConn();

    await expect(
      selectImageForPolicyBlockingReport({}, connection),
    ).resolves.toMatchObject({
      ok: false,
      status: "image_selection_error",
    });
    await expect(
      selectImageForPolicyBlockingReport(
        {
          image_digest: "sha256:a",
          image_reference: "docker.io/library/nginx:latest",
        },
        connection,
      ),
    ).resolves.toMatchObject({
      ok: false,
      status: "image_selection_error",
    });
  });
});
