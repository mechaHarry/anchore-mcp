from collections.abc import Mapping
import os
from typing import Annotated, Literal, cast
import unicodedata

import httpx
from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    model_validator,
)

from anchore_mcp.errors import AnchoreConfigurationError
from anchore_mcp.models.common import ApiVersion, validate_identifier_text


_DEFAULT_MAX_RETRIES = 2
_DEFAULT_BASE_DELAY_MS = 300
_DEFAULT_MAX_DELAY_MS = 8000
_MAX_RETRIES = 10
_MAX_DELAY_MS = 300_000


def _validate_account_header(value: str) -> str:
    validate_identifier_text(value)
    if len(value) > 1024 or not value.isascii():
        raise ValueError("account header must be at most 1024 printable ASCII characters")
    if any(not 0x20 <= ord(character) <= 0x7E for character in value):
        raise ValueError("account header must contain only printable ASCII characters")
    return value


AccountHeader = Annotated[
    str,
    Field(min_length=1, max_length=1024),
    AfterValidator(_validate_account_header),
]


class RetryPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    max_retries: Annotated[int, Field(ge=0, le=_MAX_RETRIES)] = _DEFAULT_MAX_RETRIES
    base_delay_ms: Annotated[int, Field(ge=0, le=_MAX_DELAY_MS)] = _DEFAULT_BASE_DELAY_MS
    max_delay_ms: Annotated[int, Field(ge=0, le=_MAX_DELAY_MS)] = _DEFAULT_MAX_DELAY_MS

    @model_validator(mode="after")
    def validate_delay_order(self) -> "RetryPolicy":
        if self.base_delay_ms > self.max_delay_ms:
            raise ValueError("base_delay_ms must not exceed max_delay_ms")
        return self


class AnchoreConnection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    base_url: str
    token: SecretStr
    account: AccountHeader | None = None
    api_version: ApiVersion = "v2"
    retry: RetryPolicy = Field(default_factory=RetryPolicy)

    @model_validator(mode="before")
    @classmethod
    def normalize_and_validate(cls, raw: object) -> object:
        if not isinstance(raw, Mapping):
            return raw
        values = dict(cast(Mapping[str, object], raw))
        base_url = values.get("base_url")
        if isinstance(base_url, str):
            normalized = _normalize_base_url(base_url)
            values["base_url"] = normalized
        return values

    @property
    def username(self) -> Literal["_api_key"]:
        return "_api_key"


def _normalize_base_url(value: str) -> str:
    candidate = value.strip()
    authority = candidate.partition("://")[2].split("/", 1)[0]
    if "\\" in authority or any(
        character.isspace() or unicodedata.category(character) in {"Cc", "Cs", "Zl", "Zp"}
        for character in authority
    ):
        raise ValueError("base URL authority contains whitespace or control characters")
    try:
        parsed = httpx.URL(candidate)
        hostname = parsed.host
        port = parsed.port
        if port is not None and not 1 <= port <= 65_535:
            raise ValueError("base URL port is out of range")
    except (httpx.InvalidURL, UnicodeError, ValueError) as error:
        raise ValueError("base URL authority is invalid") from error
    if parsed.scheme.casefold() != "https":
        raise ValueError("base URL must use HTTPS")
    if not hostname or not hostname.strip("."):
        raise ValueError("base URL hostname is required")
    if parsed.userinfo:
        raise ValueError("base URL must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("base URL must not contain a query or fragment")
    return str(parsed).rstrip("/")


def _required(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name)
    if value is None or not value.strip():
        raise AnchoreConfigurationError(f"{name} is required")
    return value.strip()


def _optional_integer(
    environment: Mapping[str, str], name: str, *, default: int, minimum: int, maximum: int
) -> int:
    raw = environment.get(name)
    if raw is None:
        return default
    try:
        parsed = int(raw, 10)
    except ValueError:
        return default
    return min(maximum, max(minimum, parsed))


def load_connection(env: Mapping[str, str] | None = None) -> AnchoreConnection:
    environment = os.environ if env is None else env
    base_url = _required(environment, "ANCHORE_URL")
    token = _required(environment, "ANCHORE_TOKEN")
    account_value = environment.get("ANCHORE_ACCOUNT")
    account = account_value.strip() if account_value and account_value.strip() else None
    if account is not None:
        try:
            _validate_account_header(account)
        except ValueError as error:
            raise AnchoreConfigurationError("ANCHORE_ACCOUNT is invalid") from error
    version_value = environment.get("ANCHORE_API_VERSION", "v2").strip().casefold()
    if not version_value:
        version_value = "v2"
    if version_value not in {"v1", "v2"}:
        raise AnchoreConfigurationError("ANCHORE_API_VERSION must be v1 or v2")
    api_version: ApiVersion = "v1" if version_value == "v1" else "v2"

    max_retries = _optional_integer(
        environment,
        "ANCHORE_HTTP_MAX_RETRIES",
        default=_DEFAULT_MAX_RETRIES,
        minimum=0,
        maximum=_MAX_RETRIES,
    )
    base_delay_ms = _optional_integer(
        environment,
        "ANCHORE_HTTP_RETRY_BASE_MS",
        default=_DEFAULT_BASE_DELAY_MS,
        minimum=0,
        maximum=_MAX_DELAY_MS,
    )
    max_delay_ms = _optional_integer(
        environment,
        "ANCHORE_HTTP_RETRY_MAX_MS",
        default=_DEFAULT_MAX_DELAY_MS,
        minimum=0,
        maximum=_MAX_DELAY_MS,
    )
    base_delay_ms = min(base_delay_ms, max_delay_ms)

    try:
        return AnchoreConnection(
            base_url=base_url,
            token=SecretStr(token),
            account=account,
            api_version=api_version,
            retry=RetryPolicy(
                max_retries=max_retries,
                base_delay_ms=base_delay_ms,
                max_delay_ms=max_delay_ms,
            ),
        )
    except ValidationError as error:
        raise AnchoreConfigurationError("ANCHORE_URL is invalid") from error
    except ValueError as error:
        raise AnchoreConfigurationError("ANCHORE_URL is invalid") from error


def connection_snapshot(connection: AnchoreConnection) -> dict[str, object]:
    return {
        "base_url": connection.base_url,
        "account": connection.account,
        "api_version": connection.api_version,
        "retry": connection.retry.model_dump(),
    }
