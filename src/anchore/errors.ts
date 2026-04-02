/** Base class for Anchore client failures (safe for user-facing messages). */
export class AnchoreError extends Error {
  constructor(message?: string, options?: { cause?: unknown }) {
    super(message ?? "", options);
    this.name = new.target.name;
  }
}

/** 200 response body was not valid JSON (unexpected for GET JSON helpers). */
export class AnchoreInvalidResponseError extends AnchoreError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/** HTTP failure from Anchore (4xx/5xx). `userMessage` must never contain tokens or secrets. */
export class AnchoreHttpError extends AnchoreError {
  constructor(
    readonly status: number,
    readonly userMessage: string,
    options?: { cause?: unknown },
  ) {
    super(userMessage, options);
  }
}


/** Request exceeded the configured timeout (no automatic retries). */
export class AnchoreTimeoutError extends AnchoreError {
  constructor(
    readonly timeoutMs: number,
    options?: { cause?: unknown },
  ) {
    super(
      `Request to Anchore timed out after ${timeoutMs} ms. Try again or increase timeout when supported.`,
      options,
    );
  }
}

/** Network / DNS / TLS failures before an HTTP response exists. */
export class AnchoreNetworkError extends AnchoreError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/**
 * Map HTTP status to a short operator-safe message. Does not echo response bodies
 * (they may contain internal paths or sensitive hints).
 */
export function userMessageForHttpStatus(status: number): string {
  if (status === 401 || status === 403) {
    return "Anchore denied the request — check API token, username (_api_key), account name, and RBAC.";
  }
  if (status === 404) {
    return "Anchore returned 404 — the resource or route may not exist for this deployment or version.";
  }
  if (status >= 500) {
    return "Anchore returned a server error — retry later or check Anchore service health.";
  }
  return `Anchore returned HTTP ${status}.`;
}
