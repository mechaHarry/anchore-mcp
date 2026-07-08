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
  it("returns ok when a single digest matches", async () => {
    const connection = testConn();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          items: [{ image_digest: "sha256:" + "a".repeat(64) }],
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
          items: [{ image_digest: d1 }, { image_digest: d2 }],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    const out = await resolveImageReference(connection, FQ_REF, { fetch: fetchMock });
    expect(out.kind).toBe("disambiguate");
    if (out.kind === "disambiguate") {
      expect(out.candidates).toHaveLength(2);
      expect(out.disambiguation_truncated).toBe(false);
    }
  });

  it("sets disambiguation_truncated when more than 50 unique digests", async () => {
    const connection = testConn();
    const items = Array.from({ length: 51 }, (_, i) => ({
      image_digest: `sha256:${i.toString(16).padStart(64, "0")}`,
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

  it("rejects non-FQDN references with upstream_error", async () => {
    const connection = testConn();
    const fetchMock = vi.fn();
    const out = await resolveImageReference(connection, "nginx:latest", { fetch: fetchMock });
    expect(out.kind).toBe("upstream_error");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
