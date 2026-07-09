"""Secret-safe, single-line stderr rendering and writing."""

from collections.abc import Iterable
import re
import sys
from typing import TextIO
import unicodedata


MAX_STDERR_LINE_BYTES = 512
_REDACTED = "[REDACTED]"
_TRUNCATED = "… [truncated]"

_AUTHORIZATION = re.compile(r"(?i)\bauthorization\s*:\s*[^\r\n]*")
_BEARER = re.compile(r"(?i)\bbearer\s+[^\s?#&]+")
_BASIC = re.compile(r"(?i)\bbasic\s+[^\s?#&]+")
_QUERY_SECRET = re.compile(
    r"(?i)\b(access_?token|refresh_?token|id_?token|api_?key|client_?secret|password|secret)"
    r"\s*=\s*([^&\s#]+)"
)


def _redact_patterns(text: str) -> str:
    redacted = _AUTHORIZATION.sub(f"Authorization: {_REDACTED}", text)
    redacted = _BEARER.sub(f"Bearer {_REDACTED}", redacted)
    redacted = _BASIC.sub(f"Basic {_REDACTED}", redacted)
    return _QUERY_SECRET.sub(lambda match: f"{match.group(1)}={_REDACTED}", redacted)


def _redact_configured_secrets(text: str, configured_secrets: Iterable[str]) -> str:
    redacted = text
    secrets = sorted(
        {secret for secret in configured_secrets if secret}, key=lambda value: (-len(value), value)
    )
    for secret in secrets:
        redacted = redacted.replace(secret, _REDACTED)
    return redacted


def _normalize_controls(text: str) -> str:
    return "".join(
        " " if unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"} else character
        for character in text
    )


def _truncate_utf8(text: str) -> str:
    encoded = text.encode("utf-8")
    if len(encoded) <= MAX_STDERR_LINE_BYTES:
        return text
    suffix = _TRUNCATED.encode("utf-8")
    prefix = encoded[: MAX_STDERR_LINE_BYTES - len(suffix)].decode("utf-8", errors="ignore")
    return f"{prefix}{_TRUNCATED}"


def safe_log_line(message: str, *, configured_secrets: Iterable[str] = ()) -> str:
    """Render one bounded line after redacting patterns and explicit secret values."""

    secrets = tuple(configured_secrets)
    redacted = _redact_patterns(message)
    redacted = _redact_configured_secrets(redacted, secrets)
    normalized = _normalize_controls(redacted)
    normalized = _redact_patterns(normalized)
    normalized = _redact_configured_secrets(normalized, secrets)
    return _truncate_utf8(normalized)


def log_stderr_line(
    message: str,
    *,
    configured_secrets: Iterable[str] = (),
    stream: TextIO | None = None,
) -> None:
    """Write exactly one sanitized operational line to stderr."""

    destination = sys.stderr if stream is None else stream
    destination.write(f"{safe_log_line(message, configured_secrets=configured_secrets)}\n")
