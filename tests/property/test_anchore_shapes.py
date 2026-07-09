from hypothesis import given, settings, strategies as st
import pytest

from anchore_mcp.domain.policy import interpret_policy, json_within_limits
from anchore_mcp.domain.resolution import (
    MAX_DISAMBIGUATION_CANDIDATES,
    MAX_HINTS_PER_DIGEST,
    MAX_TOTAL_DISAMBIGUATION_HINTS,
    Disambiguation,
    resolve_image_rows,
)
from anchore_mcp.errors import EnumerationIncompleteError
from anchore_mcp.tools.common import tool_error


json_scalars = st.none() | st.booleans() | st.integers() | st.text(max_size=100)
json_values = st.recursive(
    json_scalars,
    lambda children: st.lists(children, max_size=8)
    | st.dictionaries(st.text(max_size=30), children, max_size=8),
    max_leaves=40,
)


@settings(max_examples=100, derandomize=True)
@given(json_values)
def test_hostile_json_shapes_are_scanned_without_internal_exceptions(value: object) -> None:
    assert isinstance(json_within_limits(value), bool)


@settings(max_examples=25, derandomize=True)
@given(st.text(max_size=100))
def test_hostile_policy_overflow_maps_to_static_safe_tool_error(suffix: str) -> None:
    canary = "private-policy-evidence"
    payload = {"status": f"{canary}{suffix}{'x' * 4_097}"}

    with pytest.raises(EnumerationIncompleteError) as caught:
        interpret_policy(payload)

    mapped = tool_error(caught.value)
    assert str(mapped) == "Policy evidence exceeded interpretation limits"
    assert canary not in str(mapped)


def test_disambiguation_containers_never_exceed_constants() -> None:
    reference = "registry.example/team/app:1"
    rows = [
        {
            "image_digest": f"sha256:{index:064x}",
            "full_tag": reference,
            "repo_tags": [reference, *[f"registry.example/team/app:{hint}" for hint in range(20)]],
        }
        for index in range(100)
    ]

    result = resolve_image_rows(rows, reference)

    assert isinstance(result, Disambiguation)
    assert len(result.candidates) <= MAX_DISAMBIGUATION_CANDIDATES
    assert all(len(candidate.hints) <= MAX_HINTS_PER_DIGEST for candidate in result.candidates)
    assert (
        sum(len(candidate.hints) for candidate in result.candidates)
        <= MAX_TOTAL_DISAMBIGUATION_HINTS
    )
