import { describe, it, expect, vi, afterEach } from "vitest";
import {
  MAX_STDERR_LINE_CHARS,
  logStderrLine,
  redactSecrets,
} from "./safe-log.js";

describe("redactSecrets", () => {
  it("strips Basic credentials from a 401-style log line", () => {
    const token = "dGVzdDpzdXBlci1zZWNyZXQ=";
    const line = redactSecrets(
      `request failed: 401 Anchore denied Authorization: Basic ${token}`,
    );
    expect(line).toContain("Authorization: [REDACTED]");
    expect(line).not.toContain(token);
  });

  it("redacts Bearer tokens", () => {
    const line = redactSecrets("upstream said Bearer eyJhbGciOiJIUzI1NiJ.x.y");
    expect(line).not.toContain("eyJ");
    expect(line).toContain("[REDACTED]");
  });

  it("redacts common query credential keys", () => {
    const line = redactSecrets(
      "redirect https://x.test/cb?api_key=SECRET123&ok=1",
    );
    expect(line).not.toContain("SECRET123");
    expect(line).toMatch(/api_key=\[REDACTED\]/i);
  });
});

describe("logStderrLine", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("does not write an arbitrary long JSON tail (truncation)", () => {
    const spy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const tail = "UNIQUE_TAIL_FOR_STDERR_TEST_999";
    const huge = `${"a".repeat(MAX_STDERR_LINE_CHARS + 50)}${tail}`;
    logStderrLine(huge);
    const out = spy.mock.calls.map((c) => String(c[0])).join("");
    expect(out).not.toContain(tail);
    expect(out).toContain("truncated");
    expect(out.length).toBeLessThanOrEqual(MAX_STDERR_LINE_CHARS + 40);
  });

  it("applies redaction before truncate", () => {
    const spy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const secret = "dGVzdDp0b2tlbg==";
    const msg = `${"m".repeat(MAX_STDERR_LINE_CHARS)} Bearer ${secret}`;
    logStderrLine(msg);
    const out = spy.mock.calls.map((c) => String(c[0])).join("");
    expect(out).not.toContain(secret);
  });
});
