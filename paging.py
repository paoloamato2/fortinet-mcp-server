"""Bounding what a single read returns.

One read could return 1,274,739 characters -- 12x everything this server
advertises -- and a model has no way to know a call is expensive before making
it, so the bound belongs here rather than with the caller.

Two things are bounded, because bounding rows alone does not work: row size
spans 36x across the resource table, from 228 chars/row for ``waf/signature``
to 8,183 for ``system/interface``, so a flat row cap returns ~11k for one and
~409k for the other.

Imports nothing from this project, so every layer can use it with no cycle.
"""

from __future__ import annotations

import json
from typing import Any

#: Rows returned when the caller names no count.
PAGE_ROWS = 50

#: Hard bound on the serialised rows of one page. Envelope chrome (a few
#: hundred characters of vdom/serial/version keys) sits on top of this.
PAGE_CHAR_BUDGET = 25_000


class PageError(ValueError):
    """A ``start``/``count`` the caller cannot have meant."""


def normalise(start: int | None, count: int | None) -> tuple[int, int]:
    """Apply paging defaults and reject impossible values.

    Args:
        start: Row offset, or ``None`` for the first page.
        count: Rows wanted, or ``None`` for :data:`PAGE_ROWS`.

    Returns:
        The effective ``(start, count)``.

    Raises:
        PageError: If either value is not an integer, or if ``start`` is
            negative, or ``count`` is below 1. Callers convert this into the
            standard ``{"error": ...}`` payload rather than contacting the
            device.
    """
    effective_start = 0 if start is None else _as_int("start", start)
    effective_count = PAGE_ROWS if count is None else _as_int("count", count)
    if effective_start < 0:
        raise PageError(f"start must be 0 or greater, got {effective_start}.")
    if effective_count < 1:
        raise PageError(f"count must be 1 or greater, got {effective_count}.")
    return effective_start, effective_count


def _as_int(field: str, value: Any) -> int:
    """Return ``value`` as an int, or raise :class:`PageError`.

    The typed tool parameters are validated by pydantic before they reach
    here, but ``monitor_get`` also reads ``start``/``count`` out of the
    caller's ``extra_params`` JSON, where they arrive untyped. A quoted number
    -- ``{"start": "10"}`` -- would otherwise reach the comparison below and
    raise ``TypeError``, which no tool's ``except PageError`` catches, so it
    would escape to the MCP layer and break the rule that a tool returns its
    errors rather than raising them.

    ``bool`` is excluded deliberately: it subclasses ``int``, so ``True``
    would otherwise pass as a row offset of 1.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise PageError(
            f"{field} must be an integer, got {type(value).__name__} {value!r}."
        )
    return value


def page_query(start: int, count: int) -> dict[str, Any]:
    """Build the query parameters for one page.

    Asks for ``count + 1`` rows deliberately: if the extra row comes back
    there is more to fetch. CMDB reports ``size``/``next_idx`` and monitor
    reports nothing at all, so deriving ``more`` from an extra row is what
    lets both families behave identically.
    """
    return {"start": start, "count": count + 1}


def _fit_to_budget(rows: list[Any]) -> list[Any]:
    """Longest prefix of ``rows`` whose serialised size fits the budget.

    Never returns fewer than one row: a single row larger than the budget is
    returned whole, because returning nothing would leave the caller unable to
    advance ``start`` past it.
    """
    used = 0
    for index, row in enumerate(rows):
        used += len(json.dumps(row, default=str)) + 1
        if used > PAGE_CHAR_BUDGET:
            return rows[: max(1, index)]
    return rows


def paginate(payload: dict[str, Any], start: int, count: int) -> dict[str, Any]:
    """Trim one response to a page and attach ``_page``.

    Returns the payload untouched when paging is meaningless: an error dict, a
    payload with no ``results``, or ``results`` that is not a list (singletons
    and the dict-shaped monitor reads). A fan-out mapping -- produced by
    ``FanOutClient._gather`` in ``instances.py`` for ``instance="*"`` and by
    ``FortiOSClient._merge_vdom_envelopes`` in ``fortios_client.py`` for
    ``vdom="*"`` -- is paged one level down, per entry, since fan-out is
    precisely when the payload doubles.

    Never mutates ``payload``. Drops CMDB's ``next_idx``/``limit_reached``:
    both describe the device's answer to the ``count + 1`` fetch, not the
    trimmed page returned here, so leaving them in would contradict ``_page``
    -- a caller following a stale ``next_idx`` could silently skip rows.
    ``size`` is kept: ``_page.total`` is derived from it and it stays accurate
    after trimming.
    """
    if "error" in payload:
        return payload

    if "results" not in payload:
        if payload and all(isinstance(value, dict) for value in payload.values()):
            return {
                name: paginate(entry, start, count) for name, entry in payload.items()
            }
        return payload

    results = payload["results"]
    if not isinstance(results, list):
        return payload

    wanted = results[:count]
    rows = _fit_to_budget(wanted)
    total = payload.get("size")
    returned = len(rows)
    more = len(results) > count or len(rows) < len(wanted)

    paged = dict(payload)
    paged.pop("next_idx", None)
    paged.pop("limit_reached", None)
    paged["results"] = rows
    paged["_page"] = {
        "start": start,
        "returned": returned,
        "more": more,
        "next_start": start + returned if more else None,
        "total": total if isinstance(total, int) else None,
    }
    return paged
