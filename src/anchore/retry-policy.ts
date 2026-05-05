import { AnchoreHttpError, AnchoreNetworkError } from "./errors.js";

/** Retries apply only to idempotent GETs; timeouts and non-retryable HTTP errors do not loop. */
export type GetRetryPolicy = {
  /** Extra attempts after the first request (e.g. 2 → up to 3 HTTP calls total). */
  maxRetries: number;
  baseDelayMs: number;
  maxDelayMs: number;
};

const DEFAULT_POLICY: GetRetryPolicy = {
  maxRetries: 2,
  baseDelayMs: 300,
  maxDelayMs: 8_000,
};

function parsePositiveInt(raw: string | undefined, fallback: number): number {
  if (raw === undefined || raw.trim() === "") {
    return fallback;
  }
  const n = Number.parseInt(raw.trim(), 10);
  if (!Number.isFinite(n) || n < 0) {
    return fallback;
  }
  return n;
}

/**
 * Load GET retry settings from env. Used when the client does not receive an explicit policy.
 *
 * - `ANCHORE_HTTP_MAX_RETRIES` — extra attempts after the first failure (default 2).
 * - `ANCHORE_HTTP_RETRY_BASE_MS` — base backoff (default 300).
 * - `ANCHORE_HTTP_RETRY_MAX_MS` — backoff cap (default 8000).
 */
export function getGetRetryPolicyFromEnv(): GetRetryPolicy {
  return {
    maxRetries: parsePositiveInt(process.env.ANCHORE_HTTP_MAX_RETRIES, DEFAULT_POLICY.maxRetries),
    baseDelayMs: parsePositiveInt(
      process.env.ANCHORE_HTTP_RETRY_BASE_MS,
      DEFAULT_POLICY.baseDelayMs,
    ),
    maxDelayMs: parsePositiveInt(
      process.env.ANCHORE_HTTP_RETRY_MAX_MS,
      DEFAULT_POLICY.maxDelayMs,
    ),
  };
}

/** HTTP statuses where a safe GET may be retried (idempotent reads). */
export function isTransientHttpStatus(status: number): boolean {
  return status === 429 || status === 502 || status === 503 || status === 504;
}

export function shouldRetryGet(
  err: unknown,
  attemptIndex: number,
  policy: GetRetryPolicy,
): boolean {
  if (attemptIndex >= policy.maxRetries) {
    return false;
  }
  if (err instanceof AnchoreHttpError) {
    return isTransientHttpStatus(err.status);
  }
  if (err instanceof AnchoreNetworkError) {
    return true;
  }
  return false;
}

/** Parse Retry-After (seconds) when present; otherwise undefined. */
export function retryAfterDelayMs(headers: Headers): number | undefined {
  const raw = headers.get("retry-after");
  if (raw === null || raw.trim() === "") {
    return undefined;
  }
  const sec = Number.parseInt(raw.trim(), 10);
  if (!Number.isFinite(sec) || sec < 0) {
    return undefined;
  }
  return sec * 1000;
}

export function backoffDelayMs(
  attemptIndex: number,
  policy: GetRetryPolicy,
  retryAfterMs?: number,
): number {
  if (retryAfterMs !== undefined) {
    return Math.min(policy.maxDelayMs, retryAfterMs);
  }
  const exp = policy.baseDelayMs * 2 ** attemptIndex;
  const capped = Math.min(policy.maxDelayMs, exp);
  const jitter = capped * (0.5 + Math.random() * 0.5);
  return Math.round(jitter);
}

export function sleepMs(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
