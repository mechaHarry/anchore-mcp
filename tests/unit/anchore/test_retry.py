import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
import math

import pytest

from anchore_mcp.anchore.retry import (
    TRANSIENT_HTTP_STATUSES,
    backoff_seconds,
    is_transient_status,
    parse_retry_after,
    sleep_with_cancellation,
)
from anchore_mcp.config import RetryPolicy


def test_transient_http_statuses_are_exact() -> None:
    assert TRANSIENT_HTTP_STATUSES == frozenset({429, 502, 503, 504})
    for status in TRANSIENT_HTTP_STATUSES:
        assert is_transient_status(status)
    for status in (200, 400, 401, 403, 408, 500, 501, 505):
        assert not is_transient_status(status)


@pytest.mark.parametrize("status", [429, 502, 503, 504])
def test_retry_after_parser_is_available_for_every_transient_status(status: int) -> None:
    assert is_transient_status(status)
    assert parse_retry_after("2", now=datetime(2026, 7, 9, tzinfo=UTC), max_delay_s=8) == 2


@pytest.mark.parametrize(
    ("value", "expected"),
    [("0", 0.0), ("2", 2.0), (" 15 ", 8.0), ("999999999999999999999", 8.0)],
)
def test_retry_after_accepts_nonnegative_integer_seconds_and_clamps(
    value: str, expected: float
) -> None:
    assert parse_retry_after(value, now=datetime(2026, 7, 9, tzinfo=UTC), max_delay_s=8) == expected


def test_retry_after_clamps_untrusted_integer_without_unbounded_conversion() -> None:
    value = "9" * 10_000

    assert parse_retry_after(value, now=datetime(2026, 7, 9, tzinfo=UTC), max_delay_s=8) == 8


def test_retry_after_accepts_imf_fixdate_with_deterministic_clock() -> None:
    now = datetime(2026, 7, 9, 12, 0, 0, tzinfo=UTC)

    assert parse_retry_after("Thu, 09 Jul 2026 12:00:05 GMT", now=now, max_delay_s=8) == 5
    assert parse_retry_after("Thu, 09 Jul 2026 11:59:59 GMT", now=now, max_delay_s=8) == 0
    assert parse_retry_after("Thu, 09 Jul 2026 12:01:00 GMT", now=now, max_delay_s=8) == 8


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "-1",
        "+1",
        "1.5",
        "nan",
        "Thursday, 09-Jul-26 12:00:05 GMT",
        "Thu, 09 Jul 2026 12:00:05 PST",
        "Fri, 09 Jul 2026 12:00:05 GMT",
        "not-a-date",
    ],
)
def test_retry_after_rejects_malformed_negative_and_non_imf_values(value: str | None) -> None:
    assert parse_retry_after(value, now=datetime(2026, 7, 9, tzinfo=UTC), max_delay_s=8) is None


@pytest.mark.parametrize("cap", [-1.0, math.inf, -math.inf, math.nan])
def test_retry_after_rejects_invalid_caps(cap: float) -> None:
    with pytest.raises(ValueError, match="max_delay_s"):
        parse_retry_after("1", now=datetime(2026, 7, 9, tzinfo=UTC), max_delay_s=cap)


def test_retry_after_rejects_naive_clock() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        parse_retry_after("1", now=datetime(2026, 7, 9), max_delay_s=8)


def test_backoff_uses_zero_based_attempt_index_and_full_jitter() -> None:
    policy = RetryPolicy(base_delay_ms=300, max_delay_ms=8000)

    assert math.isclose(backoff_seconds(0, policy, random_value=0.5), 0.15)
    assert math.isclose(backoff_seconds(1, policy, random_value=0.5), 0.3)
    assert math.isclose(backoff_seconds(2, policy, random_value=1.0), 1.2)
    assert backoff_seconds(2, policy, random_value=0.0) == 0


def test_backoff_caps_before_jitter_and_avoids_huge_exponent_work() -> None:
    policy = RetryPolicy(base_delay_ms=300, max_delay_ms=8000)

    assert backoff_seconds(5, policy, random_value=0.5) == 4
    assert backoff_seconds(10**100, policy, random_value=1.0) == 8


def test_valid_retry_after_wins_and_is_clamped() -> None:
    policy = RetryPolicy(base_delay_ms=300, max_delay_ms=8000)

    assert backoff_seconds(0, policy, random_value=0.0, retry_after=3.5) == 3.5
    assert backoff_seconds(0, policy, random_value=1.0, retry_after=30) == 8


@pytest.mark.parametrize("attempt_index", [-1, -100])
def test_backoff_rejects_negative_attempt_indexes(attempt_index: int) -> None:
    with pytest.raises(ValueError, match="attempt_index"):
        backoff_seconds(attempt_index, RetryPolicy(), random_value=0.5)


@pytest.mark.parametrize("random_value", [-0.1, 1.1, math.inf, -math.inf, math.nan])
def test_backoff_rejects_random_values_outside_closed_unit_interval(random_value: float) -> None:
    with pytest.raises(ValueError, match="random_value"):
        backoff_seconds(0, RetryPolicy(), random_value=random_value)


@pytest.mark.parametrize("retry_after", [-1.0, math.inf, -math.inf, math.nan])
def test_backoff_rejects_invalid_retry_after_values(retry_after: float) -> None:
    with pytest.raises(ValueError, match="retry_after"):
        backoff_seconds(0, RetryPolicy(), random_value=0.5, retry_after=retry_after)


@pytest.mark.asyncio
async def test_sleep_awaits_injected_sleep() -> None:
    observed: list[float] = []

    async def fake_sleep(delay: float) -> None:
        observed.append(delay)

    await sleep_with_cancellation(1.25, sleep=fake_sleep)

    assert observed == [1.25]


@pytest.mark.asyncio
async def test_sleep_propagates_cancellation() -> None:
    async def cancelled_sleep(_delay: float) -> None:
        raise asyncio.CancelledError

    sleep: Callable[[float], Awaitable[None]] = cancelled_sleep
    with pytest.raises(asyncio.CancelledError):
        await sleep_with_cancellation(1, sleep=sleep)
