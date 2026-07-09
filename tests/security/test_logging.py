import io

from anchore_mcp.security.logging import MAX_STDERR_LINE_BYTES, log_stderr_line, safe_log_line


def test_redaction_precedes_control_normalization_and_line_cap() -> None:
    secret = "super-secret-token"
    line = f"Authorization: Basic {secret}\n" + "é" * 1000

    rendered = safe_log_line(line, configured_secrets=(secret,))

    assert secret not in rendered
    assert "[REDACTED]" in rendered
    assert len(rendered.encode("utf-8")) <= MAX_STDERR_LINE_BYTES == 512
    assert "\n" not in rendered
    assert "\r" not in rendered


def test_redacts_standalone_credentials_and_token_like_query_values() -> None:
    line = (
        "Basic dXNlcjpwYXNz Bearer header.payload.signature "
        "https://example.test/cb?api_key=api-value&refresh_token=refresh-value&ok=1 "
        "password=password-value"
    )

    rendered = safe_log_line(line)

    for secret in (
        "dXNlcjpwYXNz",
        "header.payload.signature",
        "api-value",
        "refresh-value",
        "password-value",
    ):
        assert secret not in rendered
    assert "ok=1" in rendered
    assert rendered.count("[REDACTED]") == 5


def test_configured_secrets_are_redacted_deterministically() -> None:
    rendered = safe_log_line(
        "short=abc long=abc-123 repeated=abc-123",
        configured_secrets=("", "abc", "abc-123", "abc"),
    )

    assert "abc" not in rendered
    assert rendered == "short=[REDACTED] long=[REDACTED] repeated=[REDACTED]"


def test_control_characters_are_normalized_to_one_physical_line() -> None:
    rendered = safe_log_line("first\tsecond\r\nthird\x00fourth\u2028fifth")

    assert rendered == "first second  third fourth fifth"
    assert not any(ord(character) < 32 for character in rendered)


def test_control_normalization_cannot_reveal_obfuscated_credentials() -> None:
    rendered = safe_log_line("Authorization\u200b: Basic hidden-token Bearer\u200bsecond-token")

    assert "hidden-token" not in rendered
    assert "second-token" not in rendered
    assert rendered == "Authorization: [REDACTED]"


def test_utf8_truncation_is_valid_and_bounded() -> None:
    rendered = safe_log_line("🙂" * 200)

    assert rendered.endswith("… [truncated]")
    assert len(rendered.encode("utf-8")) <= MAX_STDERR_LINE_BYTES
    rendered.encode("utf-8").decode("utf-8")


def test_stderr_helper_writes_exactly_one_sanitized_line() -> None:
    stream = io.StringIO()

    log_stderr_line("Bearer private-token\nsecond", stream=stream)

    assert stream.getvalue() == "Bearer [REDACTED] second\n"
