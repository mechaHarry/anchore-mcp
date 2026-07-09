"""Secret-safe, single-line stderr rendering and writing."""

from collections.abc import Iterable
import re
import sys
from typing import TextIO
import unicodedata
from urllib.parse import unquote


MAX_STDERR_LINE_BYTES = 512
MAX_CONFIGURED_SECRETS = 16
MAX_CONFIGURED_SECRET_LENGTH = 4_096
MAX_CONFIGURED_SECRET_TOTAL_LENGTH = 16_384
MAX_LOG_INPUT_CHARACTERS = 8_192
_REDACTED = "[REDACTED]"
_TRUNCATED = "… [truncated]"


def _spelled(word: str) -> str:
    return r"\s*".join(re.escape(character) for character in word)


_AUTHORIZATION = re.compile(rf"(?i)\b{_spelled('authorization')}\s*:\s*[^\r\n]*")
_BEARER = re.compile(rf"(?i)\b{_spelled('bearer')}\s+[^\s?#&]+")
_BASIC = re.compile(rf"(?i)\b{_spelled('basic')}\s+[^\s?#&]+")
_KEY_SEPARATOR = r"(?:\s*(?:_|-|%5f|%2d)\s*|\s*)"
_QUERY_KEYS = "|".join(
    (
        f"{_spelled('access')}{_KEY_SEPARATOR}{_spelled('token')}",
        f"{_spelled('refresh')}{_KEY_SEPARATOR}{_spelled('token')}",
        f"{_spelled('id')}{_KEY_SEPARATOR}{_spelled('token')}",
        f"{_spelled('api')}{_KEY_SEPARATOR}{_spelled('key')}",
        f"{_spelled('client')}{_KEY_SEPARATOR}{_spelled('secret')}",
        _spelled("password"),
        _spelled("secret"),
        _spelled("token"),
    )
)
_QUERY_SECRET = re.compile(rf"(?i)\b({_QUERY_KEYS})\s*=\s*([^&\s#]+)")
_QUERY_PAIR = re.compile(
    r"(?i)(?<![A-Za-z0-9_%.-])(?P<key>[A-Za-z0-9_%.-]{1,256})\s*=\s*"
    r"(?P<value>[^&\s#]+)"
)
_CANONICAL_SECRET_KEYS = frozenset(
    {
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "apikey",
        "clientsecret",
        "password",
        "secret",
        "token",
    }
)


def _redact_patterns(text: str) -> str:
    redacted = _AUTHORIZATION.sub(f"Authorization: {_REDACTED}", text)
    redacted = _BEARER.sub(f"Bearer {_REDACTED}", redacted)
    redacted = _BASIC.sub(f"Basic {_REDACTED}", redacted)
    redacted = _QUERY_SECRET.sub(lambda match: f"{match.group(1)}={_REDACTED}", redacted)

    def redact_encoded_query(match: re.Match[str]) -> str:
        decoded_key = unquote(match.group("key"))
        canonical_key = "".join(
            character for character in decoded_key.casefold() if character.isalnum()
        )
        if canonical_key in _CANONICAL_SECRET_KEYS:
            return f"{match.group('key')}={_REDACTED}"
        return match.group(0)

    return _QUERY_PAIR.sub(redact_encoded_query, redacted)


def _bounded_configured_secrets(configured_secrets: Iterable[object]) -> tuple[str, ...] | None:
    secrets: set[str] = set()
    total_length = 0
    try:
        for index, secret in enumerate(configured_secrets):
            if index >= MAX_CONFIGURED_SECRETS:
                return None
            if not isinstance(secret, str) or len(secret) > MAX_CONFIGURED_SECRET_LENGTH:
                return None
            if not secret or secret in secrets:
                continue
            total_length += len(secret)
            if total_length > MAX_CONFIGURED_SECRET_TOTAL_LENGTH:
                return None
            secrets.add(secret)
    except Exception:
        return None
    return tuple(sorted(secrets, key=lambda value: (-len(value), value)))


def _redact_configured_secrets(text: str, secrets: tuple[str, ...]) -> str:
    if not secrets:
        return text
    alternatives = "|".join(re.escape(secret) for secret in secrets)
    pattern = re.compile(rf"(?:(?:{alternatives}))+")
    return pattern.sub(_REDACTED, text)


def _redact_outside_markers(text: str, secrets: tuple[str, ...]) -> str:
    return _REDACTED.join(
        _redact_configured_secrets(part, secrets) for part in text.split(_REDACTED)
    )


def _normalize_controls(text: str) -> str:
    return "".join(
        " " if unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"} else character
        for character in text
    )


def _truncate_utf8(text: str, *, limit: int = MAX_STDERR_LINE_BYTES) -> str:
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    suffix = _TRUNCATED.encode("utf-8")
    prefix = encoded[: limit - len(suffix)].decode("utf-8", errors="ignore")
    return f"{prefix}{_TRUNCATED}"


def safe_log_line(message: str, *, configured_secrets: Iterable[str] = ()) -> str:
    """Render one bounded line after redacting patterns and explicit secret values."""

    if len(message) > MAX_LOG_INPUT_CHARACTERS:
        return f"{_REDACTED}{_TRUNCATED}"
    secrets = _bounded_configured_secrets(configured_secrets)
    if secrets is None:
        return _REDACTED
    redacted = _redact_patterns(message)
    redacted = _redact_configured_secrets(redacted, secrets)
    normalized = _normalize_controls(redacted)
    normalized = _redact_patterns(normalized)
    normalized = _redact_outside_markers(normalized, secrets)
    return _truncate_utf8(normalized)


def log_stderr_line(
    message: str,
    *,
    configured_secrets: Iterable[str] = (),
    stream: TextIO | None = None,
) -> None:
    """Write exactly one sanitized operational line to stderr."""

    destination = sys.stderr if stream is None else stream
    line = safe_log_line(message, configured_secrets=configured_secrets)
    destination.write(f"{_truncate_utf8(line, limit=MAX_STDERR_LINE_BYTES - 1)}\n")
