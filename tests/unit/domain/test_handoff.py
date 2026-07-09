from collections.abc import Sequence
from datetime import UTC, datetime
import httpx
from pydantic import JsonValue, SecretStr
import pytest

from anchore_mcp.anchore.http import JsonResponse
from anchore_mcp.config import AnchoreConnection
from anchore_mcp.domain.handoff import build_remediation_handoff
from anchore_mcp.models.locators import DigestLocator, ReferenceLocator


class StubHttp:
    def __init__(self, responses: dict[str, Sequence[tuple[JsonValue, int]]]) -> None:
        self.responses = {path: list(values) for path, values in responses.items()}
        self.calls: list[tuple[str, httpx.QueryParams]] = []

    async def get_json(
        self,
        connection: AnchoreConnection,
        path: str,
        *,
        params: httpx.QueryParams | None = None,
        max_response_bytes: int,
        timeout: httpx.Timeout | float | None = None,
    ) -> JsonResponse:
        del connection, max_response_bytes, timeout
        self.calls.append((path, params or httpx.QueryParams()))
        data, size = self.responses[path].pop(0)
        return JsonResponse(data=data, byte_length=size, headers=httpx.Headers())


def connection() -> AnchoreConnection:
    return AnchoreConnection(
        base_url="https://anchore.example/root",
        token=SecretStr("test-token"),
        account="team",
    )


@pytest.mark.asyncio
async def test_handoff_v2_has_nested_typed_evidence_exact_sizes_order_and_time() -> None:
    generated_at = datetime(2026, 7, 9, 12, 30, tzinfo=UTC)
    client = StubHttp(
        {
            "/v2/images/sha256%3Aabc": [({"detail": True}, 11)],
            "/v2/images/sha256%3Aabc/vuln/all": [({"items": []}, 13)],
            "/v2/images/sha256%3Aabc/check": [({"status": "pass"}, 17)],
        }
    )

    result = await build_remediation_handoff(
        client,
        connection(),
        DigestLocator(kind="digest", digest="sha256:abc"),
        include_policy_check=True,
        tag="registry.example/team/app:1",
        base_digest="sha256:base",
        clock=lambda: generated_at,
    )

    dumped = result.model_dump(mode="json", by_alias=True)
    assert dumped["handoffVersion"] == "2.0.0"
    assert dumped["generatedAt"] == "2026-07-09T12:30:00Z"
    assert dumped["deployment"] == {
        "baseUrl": "https://anchore.example/root",
        "account": "team",
        "apiVersion": "v2",
    }
    assert dumped["imageDigest"] == "sha256:abc"
    assert list(dumped["evidence"]) == ["detail", "vulnerabilities", "policy"]
    assert dumped["evidence"] == {
        "detail": {"data": {"detail": True}, "sizeBytes": 11},
        "vulnerabilities": {"data": {"items": []}, "sizeBytes": 13},
        "policy": {"data": {"status": "pass"}, "sizeBytes": 17},
    }
    assert dumped["totalSizeBytes"] == 41
    assert dumped["selection"] == {"complete": True, "pages_fetched": 0, "reason": None}
    policy_call = next(params for path, params in client.calls if path.endswith("/check"))
    assert policy_call == httpx.QueryParams(
        {"tag": "registry.example/team/app:1", "base_digest": "sha256:base"}
    )


@pytest.mark.asyncio
async def test_handoff_omits_policy_and_resolves_reference_once() -> None:
    reference = "registry.example/team/app:1"
    client = StubHttp(
        {
            "/v2/images": [
                (
                    {"items": [{"image_digest": "sha256:selected", "full_tag": reference}]},
                    19,
                )
            ],
            "/v2/images/sha256%3Aselected": [({"detail": True}, 5)],
            "/v2/images/sha256%3Aselected/vuln/all": [({"items": []}, 7)],
        }
    )

    result = await build_remediation_handoff(
        client,
        connection(),
        ReferenceLocator(kind="reference", reference=reference),
        include_policy_check=False,
        clock=lambda: datetime(2026, 7, 9, tzinfo=UTC),
    )

    dumped = result.model_dump(mode="json", by_alias=True)
    assert list(dumped["evidence"]) == ["detail", "vulnerabilities"]
    assert dumped["totalSizeBytes"] == 12
    assert dumped["selection"]["pages_fetched"] == 1
    assert [path for path, _params in client.calls].count("/v2/images") == 1
    assert all(not path.endswith("/check") for path, _params in client.calls)
