import { describe, expect, it, vi } from "vitest";
import type { ResolvedAnchoreConnection } from "../config/connection.js";
import { resolveImageReference } from "./resolve-image-reference.js";

function testConn(): ResolvedAnchoreConnection {
  return {
    baseUrl: "https://anchore.example.com",
    username: "_api_key",
    password: "t",
    apiVersion: "v2",
  };
}

const FQ_REF = "docker.io/library/nginx:1.21";

describe("resolveImageReference", () => {
  it("ignores a single unrelated row when the backend filter is loose", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          items: [
            {
              image_digest: "sha256:unrelated",
              full_tag: "docker.io/library/redis:7",
            },
          ],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );

    await expect(
      resolveImageReference(testConn(), FQ_REF, { fetch: fetchMock }),
    ).resolves.toEqual({ kind: "no_match" });
  });

  it("selects only the exact row from mixed backend results", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          items: [
            {
              image_digest: "sha256:exact",
              full_tag: FQ_REF,
            },
            {
              image_digest: "sha256:unrelated",
              full_tag: "docker.io/library/nginx:latest",
            },
          ],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );

    await expect(
      resolveImageReference(testConn(), FQ_REF, { fetch: fetchMock }),
    ).resolves.toEqual({ kind: "ok", digest: "sha256:exact" });
  });

  it("matches an exact reference derived from nested official image detail", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          items: [
            {
              image_digest: "sha256:nested",
              image_detail: [
                { registry: "docker.io", repo: "library/nginx", tag: "1.21" },
              ],
            },
          ],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );

    await expect(
      resolveImageReference(testConn(), FQ_REF, { fetch: fetchMock }),
    ).resolves.toEqual({ kind: "ok", digest: "sha256:nested" });
  });

  it("does not treat a nested tag component as a complete reference", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          items: [
            {
              image_digest: "sha256:synthetic",
              image_detail: {
                registry: "other.example.com",
                repo: "other/app",
                tag: FQ_REF,
              },
            },
          ],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );

    await expect(
      resolveImageReference(testConn(), FQ_REF, { fetch: fetchMock }),
    ).resolves.toEqual({ kind: "no_match" });
  });

  it("does not trust a digest row without reference evidence", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({ items: [{ image_digest: "sha256:unproven" }] }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );

    await expect(
      resolveImageReference(testConn(), FQ_REF, { fetch: fetchMock }),
    ).resolves.toEqual({ kind: "no_match" });
  });

  it("ignores a row when oversized evidence could hide the exact reference", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          items: [
            {
              image_digest: "sha256:oversized",
              full_tag: FQ_REF,
              tags: Array.from(
                { length: 300 },
                (_, index) => `docker.io/library/nginx:extra-${index}`,
              ),
            },
          ],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );

    await expect(
      resolveImageReference(testConn(), FQ_REF, { fetch: fetchMock }),
    ).resolves.toEqual({ kind: "no_match" });
  });

  it("bounds per-digest and total serialized disambiguation hints", async () => {
    const items = Array.from({ length: 10 }, (_, digestIndex) => ({
      image_digest: `sha256:${digestIndex.toString(16).padStart(64, "0")}`,
      full_tag: FQ_REF,
      tags: Array.from(
        { length: 20 },
        (_, tagIndex) =>
          `docker.io/library/nginx:d${digestIndex}-hint-${tagIndex}`,
      ),
    }));
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ items }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const out = await resolveImageReference(testConn(), FQ_REF, {
      fetch: fetchMock,
    });

    expect(out.kind).toBe("disambiguate");
    if (out.kind === "disambiguate") {
      expect(out.candidates.every((candidate) => (candidate.tags?.length ?? 0) <= 8)).toBe(true);
      expect(
        out.candidates.reduce(
          (total, candidate) => total + (candidate.tags?.length ?? 0),
          0,
        ),
      ).toBeLessThanOrEqual(64);
    }
  });

  it("matches a nested reference with a registry port and real tag", async () => {
    const requested = "registry.example.com:5000/team/app:release";
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          items: [
            {
              image_digest: "sha256:port",
              imageDetail: {
                registry: "registry.example.com:5000",
                repository: "team/app",
                tag: "release",
              },
            },
          ],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );

    await expect(
      resolveImageReference(testConn(), requested, { fetch: fetchMock }),
    ).resolves.toEqual({ kind: "ok", digest: "sha256:port" });
  });

  it("returns ok when a single digest matches", async () => {
    const connection = testConn();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          items: [
            {
              image_digest: "sha256:" + "a".repeat(64),
              full_tag: FQ_REF,
            },
          ],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    const d = `sha256:${"a".repeat(64)}`;
    const out = await resolveImageReference(connection, FQ_REF, { fetch: fetchMock });
    expect(out).toEqual({ kind: "ok", digest: d });
    expect(fetchMock.mock.calls[0][0]).toContain("full_tag=");
    expect(fetchMock.mock.calls[0][0]).not.toContain("fulltag=");
  });

  it("uses the v1 fulltag wire key", async () => {
    const d = `sha256:${"1".repeat(64)}`;
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ images: [{ image_digest: d, fulltag: FQ_REF }] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const out = await resolveImageReference(
      { ...testConn(), apiVersion: "v1" },
      FQ_REF,
      { fetch: fetchMock },
    );

    expect(out).toEqual({ kind: "ok", digest: d });
    const url = String(fetchMock.mock.calls[0][0]);
    expect(url).toContain("/v1/images?fulltag=");
    expect(url).not.toContain("full_tag=");
  });

  it("dedupes multiple rows with the same digest", async () => {
    const connection = testConn();
    const d = `sha256:${"b".repeat(64)}`;
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          items: [
            { image_digest: d, fulltag: "docker.io/library/nginx:1.21" },
            { image_digest: d, fulltag: "docker.io/library/nginx:1.21-copy" },
          ],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    const out = await resolveImageReference(connection, FQ_REF, { fetch: fetchMock });
    expect(out).toEqual({ kind: "ok", digest: d });
  });

  it("returns no_match when list is empty", async () => {
    const connection = testConn();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ items: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const out = await resolveImageReference(connection, FQ_REF, { fetch: fetchMock });
    expect(out).toEqual({ kind: "no_match" });
  });

  it("returns disambiguate when multiple digests match", async () => {
    const connection = testConn();
    const d1 = `sha256:${"c".repeat(64)}`;
    const d2 = `sha256:${"d".repeat(64)}`;
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          items: [
            { image_digest: d1, full_tag: FQ_REF },
            { image_digest: d2, full_tag: FQ_REF },
          ],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    const out = await resolveImageReference(connection, FQ_REF, { fetch: fetchMock });
    expect(out.kind).toBe("disambiguate");
    if (out.kind === "disambiguate") {
      expect(out.candidates).toEqual([
        { digest: d1, tags: [FQ_REF] },
        { digest: d2, tags: [FQ_REF] },
      ]);
      expect(out.disambiguation_truncated).toBe(false);
    }
  });

  it("sets disambiguation_truncated when more than 50 unique digests", async () => {
    const connection = testConn();
    const items = Array.from({ length: 51 }, (_, i) => ({
      image_digest: `sha256:${i.toString(16).padStart(64, "0")}`,
      full_tag: FQ_REF,
    }));
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ items }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const out = await resolveImageReference(connection, FQ_REF, { fetch: fetchMock });
    expect(out.kind).toBe("disambiguate");
    if (out.kind === "disambiguate") {
      expect(out.candidates).toHaveLength(50);
      expect(out.disambiguation_truncated).toBe(true);
    }
  });

  it("returns enumeration_incomplete when pagination caps stop the walk", async () => {
    const connection = testConn();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ images: [] }), {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          Link: '</v2/images?page=2>; rel="next"',
        },
      }),
    );
    const out = await resolveImageReference(connection, FQ_REF, {
      fetch: fetchMock,
      listCaps: { maxPages: 1, maxItems: 10_000 },
    });
    expect(out.kind).toBe("enumeration_incomplete");
  });

  it("uses the v1 query key in incomplete-enumeration guidance", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ images: [] }), {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          Link: '</v1/images?page=2>; rel="next"',
        },
      }),
    );

    const out = await resolveImageReference(
      { ...testConn(), apiVersion: "v1" },
      FQ_REF,
      { fetch: fetchMock, listCaps: { maxPages: 1, maxItems: 10_000 } },
    );

    expect(out).toMatchObject({ kind: "enumeration_incomplete" });
    if (out.kind === "enumeration_incomplete") {
      expect(out.reason).toContain("Narrow fulltag");
      expect(out.reason).not.toContain("full_tag");
    }
  });

  it("rejects non-FQDN references with upstream_error", async () => {
    const connection = testConn();
    const fetchMock = vi.fn();
    const out = await resolveImageReference(connection, "nginx:latest", { fetch: fetchMock });
    expect(out.kind).toBe("upstream_error");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects a port-only colon without fetching", async () => {
    const fetchMock = vi.fn();
    const out = await resolveImageReference(
      testConn(),
      "registry.example.com:5000/team/app",
      { fetch: fetchMock },
    );

    expect(out).toMatchObject({ kind: "upstream_error" });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
