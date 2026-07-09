import httpx
from pydantic import SecretStr
import pytest

from anchore_mcp.anchore.http import JsonResponse
from anchore_mcp.anchore.pagination import (
    LIST_CAPS,
    RESOLUTION_CAPS,
    SUMMARY_PAGE_LIMIT,
    PageCaps,
    fetch_image_pages,
    fetch_image_tag_summary_pages,
)
from anchore_mcp.config import AnchoreConnection


class StubHttp:
    def __init__(self, responses: list[JsonResponse]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, httpx.QueryParams | None, int]] = []

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
        self.calls.append((path, params, max_response_bytes))
        return self.responses.pop(0)


def connection(base_url: str = "https://xn--bcher-kva.example/enterprise") -> AnchoreConnection:
    return AnchoreConnection(base_url=base_url, token=SecretStr("secret"))


def response(data: object, *, link: str | None = None) -> JsonResponse:
    headers = httpx.Headers({"link": link} if link is not None else {})
    return JsonResponse(data=data, byte_length=2, headers=headers)  # type: ignore[arg-type]


def test_caps_are_immutable_positive_and_constants_are_bounded() -> None:
    assert LIST_CAPS == PageCaps(max_pages=200, max_items=50_000)
    assert RESOLUTION_CAPS == PageCaps(max_pages=100, max_items=20_000)
    assert SUMMARY_PAGE_LIMIT == 1000
    with pytest.raises(ValueError):
        PageCaps(max_pages=0, max_items=1)
    with pytest.raises(AttributeError):
        LIST_CAPS.max_pages = 1  # type: ignore[misc]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("body", "wrapper"),
    [
        ([{"id": "a"}], "array"),
        ({"images": [{"id": "a"}]}, "images"),
        ({"items": [{"id": "a"}]}, "items"),
    ],
)
async def test_image_pages_support_expected_wrappers(body: object, wrapper: str) -> None:
    http = StubHttp([response(body)])
    result = await fetch_image_pages(http, connection(), {"full_tag": "r/a:b"})
    assert result.rows == ({"id": "a"},)
    assert result.wrapper == wrapper
    assert result.complete is True
    assert result.incomplete_reason is None
    assert http.calls[0][0] == "/v2/images"
    assert http.calls[0][1] == httpx.QueryParams({"full_tag": "r/a:b"})


@pytest.mark.asyncio
async def test_image_pages_follow_safe_relative_and_absolute_links_with_query_encoding() -> None:
    http = StubHttp(
        [
            response(
                {"items": [{"id": "a"}]},
                link='<?page=2&q=team%2Fapp>; rel="next"',
            ),
            response(
                {"items": [{"id": "b"}]},
                link='<https://xn--bcher-kva.example:443/enterprise/v2/images?page=3>; rel="next"',
            ),
            response({"items": []}),
        ]
    )
    result = await fetch_image_pages(http, connection(), {"q": "ignored on continuation"})
    assert result.complete is True
    assert result.pages_fetched == 3
    assert http.calls[1][:2] == (
        "/v2/images",
        httpx.QueryParams("page=2&q=team%2Fapp"),
    )
    assert http.calls[2][:2] == ("/v2/images", httpx.QueryParams("page=3"))


@pytest.mark.asyncio
async def test_link_allows_other_relations_and_attributes() -> None:
    http = StubHttp(
        [
            response(
                {"items": [{"id": "a"}]},
                link='<https://xn--bcher-kva.example/enterprise/v2/images?page=1>; rel="prev", '
                '<?page=2>; type="application/json"; rel="next"',
            ),
            response({"items": []}),
        ]
    )
    result = await fetch_image_pages(http, connection(), {})
    assert result.complete is True
    assert result.pages_fetched == 2


@pytest.mark.asyncio
async def test_valid_link_does_not_hide_malformed_body_continuation() -> None:
    result = await fetch_image_pages(
        StubHttp(
            [
                response(
                    {"items": [], "next": "https://evil.example/next"},
                    link='<?page=2>; rel="next"',
                )
            ]
        ),
        connection(),
        {},
    )
    assert result.complete is False
    assert "invalid" in (result.incomplete_reason or "").lower()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "link",
    [
        "not-a-link",
        '<https://evil.example/enterprise/v2/images?page=2>; rel="next"',
        '</v2/images?page=2>; rel="next"',
        '<https://xn--bcher-kva.example/enterprise/v2/images?page=2#frag>; rel="next"',
        '<https://user@xn--bcher-kva.example/enterprise/v2/images?page=2>; rel="next"',
        '<https://xn--bcher-kva.example:444/enterprise/v2/images?page=2>; rel="next"',
    ],
)
async def test_advertised_unsafe_link_fails_closed(link: str) -> None:
    result = await fetch_image_pages(
        StubHttp([response({"items": []}, link=link)]), connection(), {}
    )
    assert result.complete is False
    assert result.incomplete_reason is not None


@pytest.mark.asyncio
async def test_body_continuations_preserve_base_query_and_detect_loops() -> None:
    http = StubHttp(
        [
            response({"images": [{"id": "a"}], "next_page_token": "a b"}),
            response({"images": [{"id": "b"}], "next": "?name=x%2Fy&page_token=a%20b"}),
        ]
    )
    result = await fetch_image_pages(http, connection(), {"name": "x/y"})
    assert result.complete is False
    assert "repeat" in (result.incomplete_reason or "").lower()
    assert http.calls[1][1] == httpx.QueryParams({"name": "x/y", "page_token": "a b"})


@pytest.mark.asyncio
async def test_malformed_wrapper_rows_and_caps_are_incomplete() -> None:
    malformed = await fetch_image_pages(StubHttp([response({"images": [1]})]), connection(), {})
    assert malformed.complete is False
    capped = await fetch_image_pages(
        StubHttp([response({"items": [{"id": 1}, {"id": 2}]})]),
        connection(),
        {},
        PageCaps(2, 1),
    )
    assert capped.rows == ({"id": 1},)
    assert capped.complete is False
    assert "max_items" in (capped.incomplete_reason or "")


@pytest.mark.asyncio
async def test_summary_uses_stable_total_and_capped_structured_page_queries() -> None:
    http = StubHttp(
        [
            response({"items": [{"id": "a"}], "total_rows": 2}),
            response({"items": [{"id": "b"}], "total_rows": 2}),
        ]
    )
    result = await fetch_image_tag_summary_pages(
        http,
        connection(),
        {"registry": "r.example", "repository": "team/app", "limit": "999999"},
        PageCaps(3, 2),
    )
    assert result.complete is True
    assert result.rows == ({"id": "a"}, {"id": "b"})
    assert http.calls[0][1] == httpx.QueryParams(
        {"registry": "r.example", "repository": "team/app", "limit": 2, "page": 1}
    )
    assert http.calls[1][1] == httpx.QueryParams(
        {"registry": "r.example", "repository": "team/app", "limit": 2, "page": 2}
    )


@pytest.mark.asyncio
async def test_summary_missing_total_follows_full_pages_until_empty() -> None:
    http = StubHttp([response({"items": [{"id": "a"}]}), response({"items": []})])
    result = await fetch_image_tag_summary_pages(http, connection(), {"limit": 1}, PageCaps(3, 3))
    assert result.complete is True
    assert result.pages_fetched == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bodies",
    [
        [{"items": [{"id": "a"}], "total_rows": 0}],
        [
            {"items": [{"id": "a"}], "total_rows": 3},
            {"items": [{"id": "b"}], "total_rows": 2},
        ],
        [{"items": [{"id": "a"}, {"id": "b"}], "total_rows": 1}],
        [{"items": [], "total_rows": 1}],
        [{"items": [], "total_rows": -1}],
    ],
)
async def test_summary_inconsistent_metadata_fails_closed(bodies: list[object]) -> None:
    result = await fetch_image_tag_summary_pages(
        StubHttp([response(body) for body in bodies]), connection(), {"limit": 1}, PageCaps(3, 3)
    )
    assert result.complete is False
    assert result.incomplete_reason is not None


@pytest.mark.asyncio
async def test_summary_page_cap_is_incomplete() -> None:
    result = await fetch_image_tag_summary_pages(
        StubHttp([response({"items": [{"id": "a"}], "total_rows": 2})]),
        connection(),
        {},
        PageCaps(1, 3),
    )
    assert result.complete is False
    assert "max_pages" in (result.incomplete_reason or "")
