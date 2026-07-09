import io

import pytest

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


@pytest.mark.parametrize(
    "message",
    [
        "api\u200b_key=hidden-token",
        "Be\u200barer hidden-token",
        "api%5Fkey=hidden-token",
        "%61pi_key=hidden-token",
        "%61%70%69%5F%6B%65%79=hidden-token",
        "%74oken=hidden-token",
        "api%255Fkey=hidden-token",
        "api_key[]=hidden-token",
        "access-token=hidden-token",
        "client%2Dsecret=hidden-token",
        "token=hidden-token",
        "a\x00p\x1fi_key=hidden-token",
    ],
)
def test_obfuscated_and_encoded_credential_forms_are_redacted(message: str) -> None:
    rendered = safe_log_line(message)

    assert "hidden-token" not in rendered
    assert "[REDACTED]" in rendered


def test_marker_overlapping_configured_secrets_cannot_amplify_output() -> None:
    rendered = safe_log_line(
        "x" * 1_000,
        configured_secrets=tuple(set("[REDACTED]")),
    )

    assert len(rendered.encode("utf-8")) <= MAX_STDERR_LINE_BYTES


def test_excessive_configured_secret_input_fails_closed() -> None:
    secrets = (str(index) for index in range(10_000))

    assert safe_log_line("ordinary message", configured_secrets=secrets) == "[REDACTED]"


def test_large_input_is_bounded_before_secret_replacement() -> None:
    rendered = safe_log_line("x" * 4_000_000, configured_secrets=("x",))

    assert len(rendered.encode("utf-8")) <= MAX_STDERR_LINE_BYTES
    assert rendered == "[REDACTED]… [truncated]"


def test_oversized_input_cannot_expose_secret_prefix_at_cutoff() -> None:
    secret = "SUPERSECRET"
    message = "Basic visible " + ("x" * 8_174) + secret

    rendered = safe_log_line(message, configured_secrets=(secret,))

    assert rendered == "[REDACTED]… [truncated]"
    assert not any(prefix in rendered for prefix in ("SUP", "SUPER", secret))


def test_utf8_truncation_is_valid_and_bounded() -> None:
    rendered = safe_log_line("🙂" * 200)

    assert rendered.endswith("… [truncated]")
    assert len(rendered.encode("utf-8")) <= MAX_STDERR_LINE_BYTES
    rendered.encode("utf-8").decode("utf-8")


def test_stderr_helper_writes_exactly_one_sanitized_line() -> None:
    stream = io.StringIO()

    log_stderr_line("Bearer private-token\nsecond", stream=stream)

    assert stream.getvalue() == "Bearer [REDACTED] second\n"


def test_stderr_physical_line_including_newline_is_bounded() -> None:
    stream = io.StringIO()

    log_stderr_line("🙂" * 1_000, stream=stream)

    assert len(stream.getvalue().encode("utf-8")) <= MAX_STDERR_LINE_BYTES
