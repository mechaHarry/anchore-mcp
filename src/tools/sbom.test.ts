import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ResolvedAnchoreConnection } from "../config/connection.js";
import * as safeLog from "../logging/safe-log.js";
import { runImageSbom } from "./sbom.js";

function testConnection(apiVersion: "v1" | "v2" = "v2"): ResolvedAnchoreConnection {
  return {
    baseUrl: "https://anchore.example.com",
    username: "_api_key",
    password: "test-token-value",
    account: "acct1",
    apiVersion,
  };
}

beforeEach(() => {
  vi.spyOn(safeLog, "logStderrLine").mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("runImageSbom", () => {
  it("returns SBOM JSON with sizeBytes for native-json (normal)", async () => {
    const connection = testConnection();
    const body = JSON.stringify({ artifacts: [] });
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(body, {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const result = await runImageSbom(
      {
        image_digest: "sha256:abc",
        format: "normal",
      },
      { connection, fetch: fetchMock },
    );
    expect(result.isError).not.toBe(true);
    const text = result.content?.[0]?.type === "text" ? result.content[0].text : "";
    const parsed = JSON.parse(text) as {
      sizeBytes: number;
      anchore: { artifacts: unknown[] };
      summary: string;
    };
    expect(parsed.sizeBytes).toBe(Buffer.byteLength(body, "utf8"));
    expect(parsed.anchore.artifacts).toEqual([]);
    expect(parsed.summary).toMatch(/KiB/);
    expect(fetchMock.mock.calls[0][0]).toBe(
      "https://anchore.example.com/v2/images/sha256%3Aabc/sboms/native-json",
    );
  });

  it("uses spdx-json path for spdx format", async () => {
    const connection = testConnection();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response("{}", { status: 200 }),
    );
    await runImageSbom(
      { image_digest: "sha256:x", format: "spdx" },
      { connection, fetch: fetchMock },
    );
    expect(fetchMock.mock.calls[0][0]).toContain("/sboms/spdx-json");
  });

  it("resolves image_reference to the same SBOM path as a matching digest", async () => {
    const connection = testConnection();
    const d = `sha256:${"a".repeat(64)}`;
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ items: [{ image_digest: d }] }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      )
      .mockResolvedValueOnce(
        new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } }),
      );
    await runImageSbom(
      {
        image_reference: "docker.io/library/nginx:1.21",
        format: "normal",
      },
      { connection, fetch: fetchMock },
    );
    expect(fetchMock.mock.calls[1][0]).toBe(
      `https://anchore.example.com/v2/images/${encodeURIComponent(d)}/sboms/native-json`,
    );
  });

  it("uses cyclonedx-json path for cyclonedx format", async () => {
    const connection = testConnection();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response("{}", { status: 200 }),
    );
    await runImageSbom(
      { image_digest: "sha256:x", format: "cyclonedx" },
      { connection, fetch: fetchMock },
    );
    expect(fetchMock.mock.calls[0][0]).toContain("/sboms/cyclonedx-json");
  });

  it("respects max_response_bytes", async () => {
    const connection = testConnection();
    const big = "x".repeat(100);
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true, pad: big }), { status: 200 }),
    );
    const result = await runImageSbom(
      {
        image_digest: "sha256:x",
        format: "normal",
        max_response_bytes: 10,
      },
      { connection, fetch: fetchMock },
    );
    expect(result.isError).toBe(true);
    const text = result.content?.[0]?.type === "text" ? result.content[0].text : "";
    const parsed = JSON.parse(text) as { message: string };
    expect(parsed.message).toMatch(/exceeding/i);
  });
});
