import { afterEach, describe, expect, it, vi } from "vitest";
import type { ResolvedAnchoreConnection } from "../config/connection.js";
import { runImageDetail, runImagePolicyCheck } from "./reports.js";

function testConnection(apiVersion: "v1" | "v2" = "v2"): ResolvedAnchoreConnection {
  return {
    baseUrl: "https://anchore.example.com",
    username: "_api_key",
    password: "test-token-value",
    account: "acct1",
    apiVersion,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("runImagePolicyCheck", () => {
  it("calls GET /v2/images/{digest}/check", async () => {
    const connection = testConnection();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ status: "pass" }), { status: 200 }),
    );
    const result = await runImagePolicyCheck(
      { image_digest: "sha256:abc" },
      { connection, fetch: fetchMock },
    );
    expect(result.isError).not.toBe(true);
    expect(fetchMock.mock.calls[0][0]).toBe(
      "https://anchore.example.com/v2/images/sha256%3Aabc/check",
    );
  });

  it("adds tag and base_digest query params when set", async () => {
    const connection = testConnection();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response("[]", { status: 200 }),
    );
    await runImagePolicyCheck(
      {
        image_digest: "sha256:abc",
        tag: "docker.io/nginx:latest",
        base_digest: "sha256:base",
      },
      { connection, fetch: fetchMock },
    );
    const url = fetchMock.mock.calls[0][0] as string;
    expect(url).toContain("tag=docker.io%2Fnginx%3Alatest");
    expect(url).toContain("base_digest=sha256%3Abase");
  });
});

describe("runImageDetail", () => {
  it("calls GET /v2/images/{digest} and includes sizeBytes", async () => {
    const connection = testConnection();
    const body = JSON.stringify({ image_digest: "sha256:abc" });
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(body, { status: 200 }),
    );
    const result = await runImageDetail(
      { image_digest: "sha256:abc" },
      { connection, fetch: fetchMock },
    );
    const text = result.content?.[0]?.type === "text" ? result.content[0].text : "";
    const parsed = JSON.parse(text) as { sizeBytes: number; anchore: unknown };
    expect(parsed.sizeBytes).toBe(Buffer.byteLength(body, "utf8"));
    expect(fetchMock.mock.calls[0][0]).toBe(
      "https://anchore.example.com/v2/images/sha256%3Aabc",
    );
  });
});
