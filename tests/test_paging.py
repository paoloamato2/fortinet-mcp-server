"""Unit tests for the pure paging helpers.

No MCP, no HTTP: these exercise the trimming and `_page` arithmetic directly,
so a failure points at the logic rather than at a tool or the client.
"""

from __future__ import annotations

import json

import pytest

from paging import (
    PAGE_CHAR_BUDGET,
    PAGE_ROWS,
    PageError,
    normalise,
    page_query,
    paginate,
)


def _envelope(rows: list[dict[str, object]], **extra: object) -> dict[str, object]:
    return {
        "http_method": "GET",
        "results": rows,
        "vdom": "root",
        "status": "success",
        **extra,
    }


def _rows(n: int, filler: int = 0) -> list[dict[str, object]]:
    return [{"name": f"row-{i}", "pad": "x" * filler} for i in range(n)]


# ----------------------------------------------------------------- normalise


def test_normalise_applies_defaults() -> None:
    assert normalise(None, None) == (0, PAGE_ROWS)


def test_normalise_keeps_explicit_values() -> None:
    assert normalise(100, 7) == (100, 7)


@pytest.mark.parametrize(("start", "count"), [(-1, None), (None, 0), (None, -3)])
def test_normalise_rejects_impossible_values(
    start: int | None, count: int | None
) -> None:
    with pytest.raises(PageError):
        normalise(start, count)


# ---------------------------------------------------------------- page_query


def test_page_query_asks_for_one_extra_row() -> None:
    """The extra row is how `more` is detected without device support."""
    assert page_query(0, 50) == {"start": 0, "count": 51}


# ------------------------------------------------------------------ paginate


def test_short_page_reports_no_more() -> None:
    result = paginate(_envelope(_rows(3)), 0, 50)
    assert result["_page"] == {"start": 0, "returned": 3, "more": False, "total": None}
    assert len(result["results"]) == 3


def test_extra_row_is_dropped_and_flags_more() -> None:
    """51 rows came back for count=50: the 51st exists only to prove `more`."""
    result = paginate(_envelope(_rows(51)), 0, 50)
    assert result["_page"]["more"] is True
    assert result["_page"]["returned"] == 50
    assert len(result["results"]) == 50


def test_total_comes_from_the_cmdb_size_field() -> None:
    result = paginate(_envelope(_rows(3), size=1344), 0, 50)
    assert result["_page"]["total"] == 1344


def test_total_is_none_when_the_api_reports_nothing() -> None:
    """Monitor endpoints report no totals; guessing would be worse."""
    assert paginate(_envelope(_rows(3)), 0, 50)["_page"]["total"] is None


def test_char_budget_trims_fat_rows_and_flags_more() -> None:
    """Row count alone does not bound size: 10 rows here exceed the budget."""
    result = paginate(_envelope(_rows(10, filler=PAGE_CHAR_BUDGET // 4)), 0, 50)
    assert result["_page"]["more"] is True
    assert result["_page"]["returned"] < 10
    assert len(json.dumps(result["results"])) <= PAGE_CHAR_BUDGET * 1.1


def test_one_oversized_row_is_still_returned() -> None:
    """Returning zero rows would strand the caller: start could never advance."""
    result = paginate(_envelope(_rows(3, filler=PAGE_CHAR_BUDGET * 2)), 0, 50)
    assert result["_page"]["returned"] == 1
    assert result["_page"]["more"] is True


def test_start_is_echoed_for_the_caller() -> None:
    assert paginate(_envelope(_rows(2)), 100, 50)["_page"]["start"] == 100


# --------------------------------------------------------- shapes not paged


def test_dict_results_are_untouched() -> None:
    """Singletons and dict-shaped monitor reads carry no page info."""
    payload = _envelope([])
    payload["results"] = {"hostname": "fw"}
    result = paginate(payload, 0, 50)
    assert "_page" not in result
    assert result["results"] == {"hostname": "fw"}


def test_error_payloads_pass_through() -> None:
    payload = {"error": "FortiOS API error 403", "status_code": 403}
    assert paginate(payload, 0, 50) == payload


def test_payload_without_results_is_untouched() -> None:
    assert paginate({"status": "success"}, 0, 50) == {"status": "success"}


# --------------------------------------------------------------- fan-out


def test_a_fan_out_mapping_is_paged_per_entry() -> None:
    """instance='*' / vdom='*' return {name: envelope}, not an envelope.

    Fan-out is exactly when the payload doubles, so it must be paged too.
    """
    mapping = {"fw-a": _envelope(_rows(51)), "fw-b": _envelope(_rows(2))}
    result = paginate(mapping, 0, 50)
    assert result["fw-a"]["_page"]["more"] is True
    assert result["fw-a"]["_page"]["returned"] == 50
    assert result["fw-b"]["_page"]["more"] is False
    assert result["fw-b"]["_page"]["returned"] == 2


def test_an_error_entry_inside_a_fan_out_mapping_survives() -> None:
    mapping = {
        "fw-a": _envelope(_rows(2)),
        "fw-b": {"error": "unreachable", "status_code": 0},
    }
    result = paginate(mapping, 0, 50)
    assert result["fw-b"] == {"error": "unreachable", "status_code": 0}
    assert result["fw-a"]["_page"]["returned"] == 2


def test_the_original_payload_is_not_mutated() -> None:
    payload = _envelope(_rows(51))
    paginate(payload, 0, 50)
    assert len(payload["results"]) == 51  # type: ignore[arg-type]
