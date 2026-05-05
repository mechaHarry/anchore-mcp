import { describe, expect, it, vi } from "vitest";
import { AnchoreHttpError, AnchoreNetworkError } from "./errors.js";
import {
  backoffDelayMs,
  getGetRetryPolicyFromEnv,
  retryAfterDelayMs,
  shouldRetryGet,
} from "./retry-policy.js";

describe("retry-policy", () => {
  it("shouldRetryGet allows network errors when attempts remain", () => {
    const policy = { maxRetries: 2, baseDelayMs: 100, maxDelayMs: 1000 };
    const err = new AnchoreNetworkError("down");
    expect(shouldRetryGet(err, 0, policy)).toBe(true);
    expect(shouldRetryGet(err, 2, policy)).toBe(false);
  });

  it("shouldRetryGet allows transient HTTP errors", () => {
    const policy = { maxRetries: 1, baseDelayMs: 100, maxDelayMs: 1000 };
    const err = new AnchoreHttpError(503, "server error");
    expect(shouldRetryGet(err, 0, policy)).toBe(true);
  });

  it("shouldRetryGet denies 401", () => {
    const policy = { maxRetries: 2, baseDelayMs: 100, maxDelayMs: 1000 };
    const err = new AnchoreHttpError(401, "nope");
    expect(shouldRetryGet(err, 0, policy)).toBe(false);
  });

  it("retryAfterDelayMs reads Retry-After seconds", () => {
    const h = new Headers({ "retry-after": "2" });
    expect(retryAfterDelayMs(h)).toBe(2000);
  });

  it("getGetRetryPolicyFromEnv reads ANCHORE_HTTP_*", () => {
    const a = process.env.ANCHORE_HTTP_MAX_RETRIES;
    const b = process.env.ANCHORE_HTTP_RETRY_BASE_MS;
    const c = process.env.ANCHORE_HTTP_RETRY_MAX_MS;
    process.env.ANCHORE_HTTP_MAX_RETRIES = "1";
    process.env.ANCHORE_HTTP_RETRY_BASE_MS = "100";
    process.env.ANCHORE_HTTP_RETRY_MAX_MS = "500";
    try {
      const p = getGetRetryPolicyFromEnv();
      expect(p.maxRetries).toBe(1);
      expect(p.baseDelayMs).toBe(100);
      expect(p.maxDelayMs).toBe(500);
    } finally {
      if (a === undefined) {
        delete process.env.ANCHORE_HTTP_MAX_RETRIES;
      } else {
        process.env.ANCHORE_HTTP_MAX_RETRIES = a;
      }
      if (b === undefined) {
        delete process.env.ANCHORE_HTTP_RETRY_BASE_MS;
      } else {
        process.env.ANCHORE_HTTP_RETRY_BASE_MS = b;
      }
      if (c === undefined) {
        delete process.env.ANCHORE_HTTP_RETRY_MAX_MS;
      } else {
        process.env.ANCHORE_HTTP_RETRY_MAX_MS = c;
      }
    }
  });

  it("backoffDelayMs respects retry-after", () => {
    const policy = { maxRetries: 2, baseDelayMs: 100, maxDelayMs: 8000 };
    expect(backoffDelayMs(0, policy, 500)).toBe(500);
  });

  it("backoffDelayMs uses jitter without retry-after", () => {
    const policy = { maxRetries: 2, baseDelayMs: 100, maxDelayMs: 8000 };
    vi.spyOn(Math, "random").mockReturnValue(0);
    try {
      expect(backoffDelayMs(0, policy)).toBe(50);
    } finally {
      vi.mocked(Math.random).mockRestore();
    }
  });
});
