"""Bounded, request-scoped retry timing helpers for idempotent Anchore reads."""

import asyncio
from collections.abc import Awaitable, Callable
from datetime import datetime
from email.utils import format_datetime, parsedate_to_datetime
import math
import sys

from anchore_mcp.config import RetryPolicy


TRANSIENT_HTTP_STATUSES: frozenset[int] = frozenset({429, 502, 503, 504})


def is_transient_status(status: int) -> bool:
    return status in TRANSIENT_HTTP_STATUSES


def _validated_cap(max_delay_s: float) -> float:
    if not math.isfinite(max_delay_s) or max_delay_s < 0:
        raise ValueError("max_delay_s must be finite and nonnegative")
    return float(max_delay_s)


def parse_retry_after(value: str | None, *, now: datetime, max_delay_s: float) -> float | None:
    """Parse Retry-After delta-seconds or canonical IMF-fixdate, bounded by a cap."""

    cap = _validated_cap(max_delay_s)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    if value is None:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    if candidate.isascii() and candidate.isdecimal():
        normalized = candidate.lstrip("0") or "0"
        if len(normalized) > sys.float_info.max_10_exp + 1:
            return cap
        return float(min(int(normalized, 10), cap))

    try:
        parsed = parsedate_to_datetime(candidate)
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    try:
        if format_datetime(parsed, usegmt=True) != candidate:
            return None
    except ValueError:
        return None
    delay = max(0.0, (parsed - now).total_seconds())
    return min(delay, cap)


def backoff_seconds(
    attempt_index: int,
    policy: RetryPolicy,
    random_value: float,
    retry_after: float | None = None,
) -> float:
    """Return full-jitter backoff for a zero-based retry attempt."""

    if attempt_index < 0:
        raise ValueError("attempt_index must be nonnegative")
    if not math.isfinite(random_value) or not 0 <= random_value <= 1:
        raise ValueError("random_value must be finite and between 0 and 1")

    cap = policy.max_delay_ms / 1000
    if retry_after is not None:
        if not math.isfinite(retry_after) or retry_after < 0:
            raise ValueError("retry_after must be finite and nonnegative")
        return min(float(retry_after), cap)

    base = policy.base_delay_ms / 1000
    if base == 0 or cap == 0:
        ceiling = 0.0
    elif base >= cap:
        ceiling = cap
    else:
        cap_attempt = math.ceil(math.log2(cap / base))
        ceiling = cap if attempt_index >= cap_attempt else math.ldexp(base, attempt_index)
    return random_value * ceiling


async def sleep_with_cancellation(
    delay_s: float,
    *,
    sleep: Callable[[float], Awaitable[None]] | None = None,
) -> None:
    """Await a delay without intercepting task cancellation."""

    sleep_function = asyncio.sleep if sleep is None else sleep
    await sleep_function(delay_s)
