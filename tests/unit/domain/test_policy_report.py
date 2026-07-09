from collections.abc import Sequence
from typing import cast

import httpx
from pydantic import JsonValue, SecretStr
import pytest

from anchore_mcp.anchore.http import JsonResponse
from anchore_mcp.anchore.openapi import OpenApiCache
from anchore_mcp.config import AnchoreConnection
from anchore_mcp.domain.policy_report import (
    POLICY_VULNERABILITY_MAX_RESPONSE_BYTES,
    build_policy_blocking_report,
)
from anchore_mcp.errors import EnumerationIncompleteError, TrustEvidenceError
from anchore_mcp.models.locators import DigestLocator, ReferenceLocator


REFERENCE = "registry.example/team/app:1"


class RecordingHttp:
    def __init__(self, responses: dict[str, Sequence[object]]) -> None:
        self.responses = {path: list(values) for path, values in responses.items()}
        self.calls: list[tuple[str, httpx.QueryParams, int]] = []

    async def get_json(
        self,
        connection: AnchoreConnection,
        path: str,
        *,
        params: httpx.QueryParams | None = None,
        max_response_bytes: int,
        timeout: httpx.Timeout | float | None = None,
    ) -> JsonResponse:
        del connection, timeout
        self.calls.append((path, params or httpx.QueryParams(), max_response_bytes))
        value = self.responses[path].pop(0)
        return JsonResponse(data=cast(JsonValue, value), byte_length=2, headers=httpx.Headers())


def connection() -> AnchoreConnection:
    return AnchoreConnection(
        base_url="https://anchore.example",
        token=SecretStr("test-token"),
        account="team",
    )


@pytest.mark.asyncio
async def test_green_policy_skips_vulnerability_request() -> None:
    client = RecordingHttp({"/v2/images/sha256%3Aabc/check": [{"status": "green"}]})

    result = await build_policy_blocking_report(
        client,
        connection(),
        DigestLocator(kind="digest", digest="sha256:abc"),
        OpenApiCache(client),
    )

    assert result.outcome == "already_green"
    assert result.selection.complete is True
    assert result.selection.pages_fetched == 0
    assert result.blockers == []
    assert [path for path, _params, _limit in client.calls] == ["/v2/images/sha256%3Aabc/check"]


@pytest.mark.asyncio
async def test_policy_interpretation_overflow_fails_closed_before_vulnerability_request() -> None:
    policy: object = {"status": "unknown"}
    for _ in range(34):
        policy = {"nested": policy}
    client = RecordingHttp({"/v2/images/sha256%3Aabc/check": [policy]})

    with pytest.raises(EnumerationIncompleteError):
        await build_policy_blocking_report(
            client,
            connection(),
            DigestLocator(kind="digest", digest="sha256:abc"),
            OpenApiCache(client),
        )

    assert [path for path, _params, _limit in client.calls] == ["/v2/images/sha256%3Aabc/check"]


@pytest.mark.asyncio
async def test_reference_selection_state_and_default_policy_tag_are_truthful() -> None:
    client = RecordingHttp(
        {
            "/v2/images": [
                {
                    "items": [
                        {
                            "image_digest": "sha256:selected",
                            "full_tag": REFERENCE,
                            "analyzed_at": "2026-04-02T00:00:00Z",
                        }
                    ]
                }
            ],
            "/v2/images/sha256%3Aselected/check": [{"result": "pass"}],
        }
    )

    result = await build_policy_blocking_report(
        client,
        connection(),
        ReferenceLocator(kind="reference", reference=REFERENCE),
        OpenApiCache(client),
    )

    assert result.selection.complete is True
    assert result.selection.pages_fetched == 1
    assert client.calls[1][1].get("tag") == REFERENCE


@pytest.mark.asyncio
async def test_red_policy_fetches_bounded_vulnerabilities_and_exactly_joins() -> None:
    policy = {
        "status": "red",
        "findings": [
            {
                "gate": "vulnerabilities",
                "action": "stop",
                "vulnerability_id": "CVE-2099-0001",
            }
        ],
    }
    vulnerabilities = {
        "items": [
            {
                "vuln": "CVE-2099-0001",
                "package_name": "openssl",
                "package_version": "1.0",
                "path": "/usr/lib/libssl.so",
            },
            {"vuln": "CVE-2099-9999"},
        ]
    }
    client = RecordingHttp(
        {
            "/v2/images/sha256%3Aabc/check": [policy],
            "/v2/images/sha256%3Aabc/vuln/all": [vulnerabilities],
        }
    )

    result = await build_policy_blocking_report(
        client,
        connection(),
        DigestLocator(kind="digest", digest="sha256:abc"),
        OpenApiCache(client),
        tag="explicit:tag",
        base_digest="sha256:base",
    )

    assert result.outcome == "blocked"
    assert len(result.blockers) == 1
    blocker = result.blockers[0]
    assert isinstance(blocker, dict)
    vulnerability = blocker["vulnerability"]
    assert isinstance(vulnerability, dict)
    assert vulnerability["vulnerability_id"] == "CVE-2099-0001"
    assert [path for path, _params, _limit in client.calls] == [
        "/v2/images/sha256%3Aabc/check",
        "/v2/images/sha256%3Aabc/vuln/all",
    ]
    assert client.calls[0][1] == httpx.QueryParams(
        {"tag": "explicit:tag", "base_digest": "sha256:base"}
    )
    assert client.calls[1][2] == POLICY_VULNERABILITY_MAX_RESPONSE_BYTES == 20 * 1024 * 1024


@pytest.mark.asyncio
async def test_non_green_without_exact_join_raises_static_trust_error() -> None:
    client = RecordingHttp(
        {
            "/v2/images/sha256%3Aabc/check": [
                {
                    "status": "red",
                    "findings": [
                        {
                            "gate": "vulnerabilities",
                            "action": "stop",
                            "vulnerability_id": "CVE-2099-0001",
                        }
                    ],
                }
            ],
            "/v2/images/sha256%3Aabc/vuln/all": [{"items": [{"vuln": "CVE-2099-9999"}]}],
        }
    )

    with pytest.raises(
        TrustEvidenceError, match="red policy has no proven vulnerability remediation"
    ):
        await build_policy_blocking_report(
            client,
            connection(),
            DigestLocator(kind="digest", digest="sha256:abc"),
            OpenApiCache(client),
        )
