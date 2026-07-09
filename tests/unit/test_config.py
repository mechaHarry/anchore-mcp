import pytest
from pydantic import SecretStr, ValidationError

from anchore_mcp.config import AnchoreConnection, RetryPolicy, connection_snapshot, load_connection
from anchore_mcp.errors import (
    AnchoreConfigurationError,
    AnchoreError,
    AnchoreHttpError,
    AnchoreInvalidResponseError,
    AnchoreNetworkError,
    AnchoreResponseTooLargeError,
    AnchoreTimeoutError,
    EnumerationIncompleteError,
    TrustEvidenceError,
)


def required_env(**overrides: str) -> dict[str, str]:
    return {
        "ANCHORE_URL": "https://anchore.example/",
        "ANCHORE_TOKEN": "test-secret-value",
        **overrides,
    }


def test_connection_normalizes_https_url_and_defaults() -> None:
    connection = load_connection(required_env())

    assert connection.base_url == "https://anchore.example"
    assert connection.api_version == "v2"
    assert connection.account is None
    assert connection.username == "_api_key"
    assert connection.retry == RetryPolicy(max_retries=2, base_delay_ms=300, max_delay_ms=8000)


@pytest.mark.parametrize(
    "url", ["http://anchore.example", "anchore.example", "ftp://anchore.example"]
)
def test_connection_requires_https(url: str) -> None:
    with pytest.raises(AnchoreConfigurationError, match="ANCHORE_URL"):
        load_connection(required_env(ANCHORE_URL=url))


@pytest.mark.parametrize("name", ["ANCHORE_URL", "ANCHORE_TOKEN"])
@pytest.mark.parametrize("value", ["", " ", "\t"])
def test_required_connection_values_reject_missing_or_blank(name: str, value: str) -> None:
    env = required_env()
    env[name] = value

    with pytest.raises(AnchoreConfigurationError, match=name):
        load_connection(env)


def test_load_connection_reads_os_environ_only_when_called(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANCHORE_URL", "https://lazy.example/")
    monkeypatch.setenv("ANCHORE_TOKEN", "lazy-secret")

    connection = load_connection()

    assert connection.base_url == "https://lazy.example"


def test_account_blank_becomes_none_and_nonblank_is_trimmed() -> None:
    assert load_connection(required_env(ANCHORE_ACCOUNT=" ")).account is None
    assert load_connection(required_env(ANCHORE_ACCOUNT=" team ")).account == "team"


@pytest.mark.parametrize(("value", "expected"), [("V1", "v1"), ("v2", "v2")])
def test_api_version_is_case_normalized(value: str, expected: str) -> None:
    assert load_connection(required_env(ANCHORE_API_VERSION=value)).api_version == expected


def test_blank_api_version_uses_default() -> None:
    assert load_connection(required_env(ANCHORE_API_VERSION=" ")).api_version == "v2"


def test_invalid_api_version_is_safe() -> None:
    secret = "never-expose-this-token"

    with pytest.raises(AnchoreConfigurationError) as caught:
        load_connection(required_env(ANCHORE_TOKEN=secret, ANCHORE_API_VERSION="v3"))

    assert secret not in str(caught.value)
    assert secret not in repr(caught.value)


def test_retry_environment_parses_valid_integers() -> None:
    connection = load_connection(
        required_env(
            ANCHORE_HTTP_MAX_RETRIES="5",
            ANCHORE_HTTP_RETRY_BASE_MS="750",
            ANCHORE_HTTP_RETRY_MAX_MS="12000",
        )
    )

    assert connection.retry == RetryPolicy(max_retries=5, base_delay_ms=750, max_delay_ms=12000)


def test_invalid_retry_integers_fall_back_to_defaults() -> None:
    connection = load_connection(
        required_env(
            ANCHORE_HTTP_MAX_RETRIES="not-a-number",
            ANCHORE_HTTP_RETRY_BASE_MS="3.5",
            ANCHORE_HTTP_RETRY_MAX_MS="",
        )
    )

    assert connection.retry == RetryPolicy()


def test_out_of_bounds_retry_values_are_clamped_to_finite_limits() -> None:
    connection = load_connection(
        required_env(
            ANCHORE_HTTP_MAX_RETRIES="999",
            ANCHORE_HTTP_RETRY_BASE_MS="-1",
            ANCHORE_HTTP_RETRY_MAX_MS="999999999",
        )
    )

    assert connection.retry == RetryPolicy(max_retries=10, base_delay_ms=0, max_delay_ms=300_000)


def test_retry_policy_rejects_base_above_max() -> None:
    with pytest.raises(ValidationError, match="base_delay_ms"):
        RetryPolicy(base_delay_ms=9000, max_delay_ms=8000)


def test_retry_environment_clamps_base_to_selected_maximum() -> None:
    connection = load_connection(
        required_env(ANCHORE_HTTP_RETRY_BASE_MS="9000", ANCHORE_HTTP_RETRY_MAX_MS="8000")
    )

    assert connection.retry.base_delay_ms == 8000
    assert connection.retry.max_delay_ms == 8000


def test_connection_repr_dump_snapshot_and_errors_never_contain_token() -> None:
    secret = "never-expose-this-token"
    connection = load_connection(required_env(ANCHORE_TOKEN=secret))
    rendered = " ".join(
        [
            repr(connection),
            str(connection),
            str(connection.model_dump()),
            str(connection_snapshot(connection)),
        ]
    )

    assert secret not in rendered
    assert "token" not in str(connection_snapshot(connection)).casefold()
    assert "username" not in str(connection_snapshot(connection)).casefold()

    with pytest.raises(ValidationError) as caught:
        AnchoreConnection(base_url="http://invalid", token=SecretStr(secret))
    assert secret not in str(caught.value)

    with pytest.raises(ValidationError) as raw_input_caught:
        AnchoreConnection.model_validate({"base_url": "http://invalid", "token": secret})
    assert secret not in str(raw_input_caught.value)


def test_connection_validation_errors_hide_secret_fragments_and_extra_values() -> None:
    secret = "recognizable-prefix-" + ("s" * 96) + "-recognizable-suffix"

    with pytest.raises(ValidationError) as caught:
        AnchoreConnection.model_validate(
            {
                "base_url": "https://anchore.example",
                "token": secret,
                "unexpected_secret": secret,
            }
        )

    rendered = f"{caught.value!s} {caught.value!r}"
    for fragment in (secret, "recognizable-prefix", "recognizable-suffix"):
        assert fragment not in rendered


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com:abc",
        "https://example.com:99999",
        "https://exa mple.com",
        "https://example.com\t.evil",
        "https://\x00example.com",
        "https://:443",
        "https://.",
        "https://example.com\\evil",
        "https://exa\u202emple.com",
    ],
)
def test_connection_rejects_malformed_url_authorities(url: str) -> None:
    with pytest.raises(AnchoreConfigurationError, match="ANCHORE_URL"):
        load_connection(required_env(ANCHORE_URL=url))


@pytest.mark.parametrize("url", ["https://localhost", "https://127.0.0.1", "https://[::1]"])
def test_connection_allows_local_and_internal_style_hosts(url: str) -> None:
    assert load_connection(required_env(ANCHORE_URL=url)).base_url == url


def test_connection_rejects_account_header_injection() -> None:
    with pytest.raises(AnchoreConfigurationError, match="ANCHORE_ACCOUNT"):
        load_connection(required_env(ANCHORE_ACCOUNT="team\r\nx-injected: yes"))


def test_explicit_environment_mapping_does_not_merge_process_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANCHORE_TOKEN", "process-secret")

    with pytest.raises(AnchoreConfigurationError, match="ANCHORE_TOKEN"):
        load_connection({"ANCHORE_URL": "https://anchore.example"})


def test_safe_exception_taxonomy_exposes_only_public_messages() -> None:
    http_error = AnchoreHttpError(503, "Anchore is temporarily unavailable")
    timeout_error = AnchoreTimeoutError("read")
    size_error = AnchoreResponseTooLargeError(observed=101, max=100)
    exceptions: list[AnchoreError] = [
        AnchoreConfigurationError("Configuration is unavailable"),
        http_error,
        AnchoreInvalidResponseError("Anchore returned an invalid response"),
        AnchoreNetworkError("Anchore could not be reached"),
        timeout_error,
        size_error,
        EnumerationIncompleteError("Enumeration was incomplete"),
        TrustEvidenceError("Required trust evidence is incomplete"),
    ]

    rendered = " ".join(str(error) for error in exceptions)
    assert "secret-body" not in rendered
    assert str(http_error) == "Anchore is temporarily unavailable"
    assert http_error.status == 503
    assert timeout_error.phase == "read"
    assert size_error.observed == 101
    assert size_error.max == 100
