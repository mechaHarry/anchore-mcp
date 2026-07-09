from collections.abc import Sequence
from types import SimpleNamespace
from typing import cast

from fastmcp import Context
from fastmcp.exceptions import ToolError
import httpx
from pydantic import JsonValue, SecretStr
import pytest

from anchore_mcp.anchore.http import JsonResponse
from anchore_mcp.anchore.openapi import OpenApiCache
from anchore_mcp.config import AnchoreConnection
from anchore_mcp.runtime import Runtime
from anchore_mcp.tools.list_images import MAX_LIST_TOTAL_BYTES, anchore_list_images


class StubHttp:
    def __init__(self, responses: Sequence[JsonResponse | Exception]) -> None:
        self.responses = list(responses)
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
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def response(data: JsonValue, *, byte_length: int = 10, link: str | None = None) -> JsonResponse:
    headers = httpx.Headers({} if link is None else {"Link": link})
    return JsonResponse(data=data, byte_length=byte_length, headers=headers)


def connection() -> AnchoreConnection:
    return AnchoreConnection(
        base_url="https://anchore.example",
        token=SecretStr("private-token"),
        account="team",
        api_version="v2",
    )


def fake_context(http: StubHttp, *, mapping: bool = False) -> Context:
    runtime = Runtime(
        http_client=cast(httpx.AsyncClient, SimpleNamespace()),
        anchore_http=cast(object, http),  # type: ignore[arg-type]
        openapi_cache=OpenApiCache(http),
    )
    lifespan: object = {"runtime": runtime} if mapping else runtime
    return cast(Context, SimpleNamespace(lifespan_context=lifespan))


@pytest.mark.asyncio
async def test_list_images_applies_bounded_allowlisted_query_and_reports_rejections(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    http = StubHttp(
        [
            response(
                {
                    "paths": {
                        "/v2/images": {"get": {"parameters": [{"name": "name", "in": "query"}]}}
                    }
                },
                byte_length=100,
            ),
            response({"items": [{"image_digest": "sha256:a"}]}, byte_length=23),
        ]
    )
    monkeypatch.setattr("anchore_mcp.tools.list_images.load_connection", connection)

    result = await anchore_list_images(
        fake_context(http, mapping=True),
        fulltag="registry.example/team/app:1",
        vulnerability_id="CVE-2099-1234",
        list_query={"name": "sample", "not_allowed": "value"},
    )

    assert http.calls[0][0] == "/v2/openapi.json"
    assert http.calls[1][:2] == (
        "/v2/images",
        httpx.QueryParams(
            {
                "full_tag": "registry.example/team/app:1",
                "vulnerability_id": "CVE-2099-1234",
                "name": "sample",
            }
        ),
    )
    assert result.structured_content is not None
    assert result.structured_content["images"] == [{"image_digest": "sha256:a"}]
    assert result.structured_content["enumeration"] == {
        "complete": True,
        "pages_fetched": 1,
        "reason": None,
    }
    assert result.structured_content["size_bytes"] == 23
    assert "not_allowed" in " ".join(cast(list[str], result.structured_content["warnings"]))
    assert "private-token" not in str(result.structured_content)


@pytest.mark.asyncio
async def test_list_images_returns_explicit_incomplete_enumeration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    http = StubHttp(
        [response({"items": [{"image_digest": "sha256:a"}]}, byte_length=17, link="invalid")]
    )
    monkeypatch.setattr("anchore_mcp.tools.list_images.load_connection", connection)

    result = await anchore_list_images(fake_context(http))

    assert result.structured_content is not None
    assert result.structured_content["enumeration"]["complete"] is False
    assert "invalid Link" in cast(str, result.structured_content["enumeration"]["reason"])
    assert result.structured_content["size_bytes"] == 17


@pytest.mark.asyncio
async def test_list_images_counts_all_page_bytes_and_preserves_raw_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    http = StubHttp(
        [
            response(
                {"items": [{"owner": "person@example.test"}]},
                byte_length=11,
                link='</v2/images?page=2>; rel="next"',
            ),
            response({"items": [{"image_digest": "sha256:b"}]}, byte_length=13),
        ]
    )
    monkeypatch.setattr("anchore_mcp.tools.list_images.load_connection", connection)

    result = await anchore_list_images(fake_context(http))

    assert result.structured_content is not None
    assert result.structured_content["size_bytes"] == 24
    assert result.structured_content["images"][0]["owner"] == "person@example.test"
    assert len(result.structured_content["images"]) == 2
    assert [call[2] for call in http.calls] == [MAX_LIST_TOTAL_BYTES, MAX_LIST_TOTAL_BYTES - 11]


@pytest.mark.asyncio
async def test_list_images_enforces_one_aggregate_decoded_byte_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_size = (MAX_LIST_TOTAL_BYTES // 2) + 1
    http = StubHttp(
        [
            response(
                {"items": [{"image_digest": "sha256:first"}]},
                byte_length=first_size,
                link='</v2/images?page=2>; rel="next"',
            ),
            response(
                {"items": [{"image_digest": "sha256:must-not-be-retained"}]},
                byte_length=first_size,
            ),
        ]
    )
    monkeypatch.setattr("anchore_mcp.tools.list_images.load_connection", connection)

    with pytest.raises(ToolError, match="response exceeded"):
        await anchore_list_images(fake_context(http))

    assert len(http.calls) == 2
    assert [call[2] for call in http.calls] == [
        MAX_LIST_TOTAL_BYTES,
        MAX_LIST_TOTAL_BYTES - first_size,
    ]


@pytest.mark.asyncio
async def test_list_images_enforces_32_applied_keys_and_value_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = [f"filter_{index:02d}" for index in range(34)]
    http = StubHttp(
        [
            response(
                {
                    "paths": {
                        "/v2/images": {
                            "get": {"parameters": [{"name": key, "in": "query"} for key in keys]}
                        }
                    }
                }
            ),
            response({"items": []}),
        ]
    )
    monkeypatch.setattr("anchore_mcp.tools.list_images.load_connection", connection)
    query = {key: "value" for key in keys}
    query["filter_00"] = "x" * 4_097

    result = await anchore_list_images(fake_context(http), list_query=query)

    assert len(http.calls[1][1].keys()) == 32
    assert "filter_00" not in http.calls[1][1]
    assert result.structured_content is not None
    warning_text = " ".join(cast(list[str], result.structured_content["warnings"]))
    assert "Dropped 2" in warning_text


@pytest.mark.asyncio
async def test_list_images_masks_rejected_key_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    http = StubHttp([response({"paths": {}}), response({"items": []})])
    monkeypatch.setattr("anchore_mcp.tools.list_images.load_connection", connection)

    result = await anchore_list_images(
        fake_context(http), list_query={"person@example.test": "value"}
    )

    assert result.structured_content is not None
    warnings = " ".join(cast(list[str], result.structured_content["warnings"]))
    assert "person@example.test" not in warnings
    assert "[email redacted]" in warnings


@pytest.mark.asyncio
async def test_list_images_reports_unexamined_entries_after_safety_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    http = StubHttp([response({"paths": {}}), response({"items": []})])
    monkeypatch.setattr("anchore_mcp.tools.list_images.load_connection", connection)

    result = await anchore_list_images(
        fake_context(http),
        list_query={f"unsupported_{index:02d}": "value" for index in range(65)},
    )

    assert result.structured_content is not None
    warnings = " ".join(cast(list[str], result.structured_content["warnings"]))
    assert "not examined" in warnings


@pytest.mark.asyncio
async def test_list_images_missing_runtime_is_generic_tool_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("anchore_mcp.tools.list_images.load_connection", connection)

    with pytest.raises(ToolError, match="failed safely"):
        await anchore_list_images(cast(Context, SimpleNamespace(lifespan_context={})))


@pytest.mark.asyncio
async def test_list_images_unknown_error_never_logs_exception_text(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    http = StubHttp([RuntimeError("Bearer private-token person@example.test")])
    monkeypatch.setattr("anchore_mcp.tools.list_images.load_connection", connection)

    with pytest.raises(ToolError, match="failed safely") as raised:
        await anchore_list_images(fake_context(http))
    captured = capsys.readouterr()

    assert raised.value.__cause__ is None
    assert "RuntimeError" in captured.err
    assert "private-token" not in captured.err
    assert "person@example.test" not in captured.err
    assert captured.out == ""


@pytest.mark.asyncio
async def test_list_images_missing_configuration_is_safe_tool_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ANCHORE_URL", raising=False)
    monkeypatch.delenv("ANCHORE_TOKEN", raising=False)

    with pytest.raises(ToolError) as raised:
        await anchore_list_images(cast(Context, SimpleNamespace(lifespan_context={})))

    assert "token" not in str(raised.value).casefold()
    assert "traceback" not in str(raised.value).casefold()
