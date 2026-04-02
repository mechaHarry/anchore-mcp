/**
 * R13 — stderr logging: redact secrets; never log full tool JSON bodies at default levels.
 *
 * Callers must not pass complete API response or tool-result JSON here. Use short diagnostic
 * strings or `logStderrLine` with pre-sized fields. Debug logging that needs more detail should
 * be gated and documented separately.
 */

/** Max characters written per log line after redaction (avoids dumping large JSON to stderr). */
export const MAX_STDERR_LINE_CHARS = 512;

function replaceAll(
  input: string,
  pattern: RegExp,
  replacement: string,
): string {
  return input.replace(pattern, replacement);
}

/**
 * Redact common secret patterns (Authorization, Bearer, Basic, obvious query tokens).
 * Does not guarantee zero leakage from arbitrary binary data — callers still avoid logging bodies.
 */
export function redactSecrets(text: string): string {
  let out = text;

  out = replaceAll(
    out,
    /Authorization\s*:\s*[^\n\r]+/gi,
    "Authorization: [REDACTED]",
  );
  out = replaceAll(out, /\bBearer\s+\S+/gi, "Bearer [REDACTED]");
  out = replaceAll(
    out,
    /\bBasic\s+[A-Za-z0-9+/=]{4,}={0,2}\b/gi,
    "Basic [REDACTED]",
  );
  out = replaceAll(
    out,
    /\b(access_?token|refresh_?token|id_?token|api_?key|client_?secret|password|secret)=([^&\s#]+)/gi,
    "$1=[REDACTED]",
  );

  return out;
}

function truncateForStderr(redacted: string): string {
  if (redacted.length <= MAX_STDERR_LINE_CHARS) {
    return redacted;
  }
  return `${redacted.slice(0, MAX_STDERR_LINE_CHARS)}… [truncated]`;
}

/**
 * Write one line to stderr after secret redaction and length cap.
 * Do not pass full JSON tool payloads or Anchore response bodies.
 */
export function logStderrLine(message: string): void {
  const line = truncateForStderr(redactSecrets(message));
  process.stderr.write(`${line}\n`);
}
