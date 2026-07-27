"""Contract tests for MCP tool annotations.

Annotations are advertisement: a client reads them to decide what it may
auto-approve, what it must confirm and what it should surface to a human.
A wrong hint is therefore a safety bug -- a tool that reconfigures a
production firewall while advertising ``readOnlyHint=true`` is precisely
the failure a gating client cannot defend against. These tests exist so
that failure has to be made deliberately.

See ``docs/superpowers/specs/2026-07-27-mcp-tool-annotations-design.md``
for where the read-only line falls and why.
"""

from __future__ import annotations

import tool_annotations
from tool_annotations import CATEGORIES, READ_ONLY

#: The four hint fields the MCP spec defines. ``ToolAnnotations`` also has
#: ``title``, which is a display string rather than a safety hint and is
#: deliberately left unset.
HINT_FIELDS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")


def test_categories_are_pairwise_distinct() -> None:
    """No two named categories may carry the same four hints.

    Two names for one hint combination would make the category a comment
    rather than a contract: the identity check in
    ``test_every_tool_uses_an_approved_category`` could not tell which one
    a tool meant, and a reviewer reading ``UPDATES`` would have no
    guarantee it differs from ``CREATES`` on the wire.
    """
    seen: dict[tuple[object, ...], str] = {}
    for name, ann in CATEGORIES.items():
        key = tuple(getattr(ann, field) for field in HINT_FIELDS)
        assert key not in seen, f"{name} duplicates {seen[key]}: {key}"
        seen[key] = name


def test_every_category_sets_all_four_hints() -> None:
    """Including the two the spec calls meaningful only for writers.

    ``destructiveHint`` defaults to *true* on the wire, so a reader that
    omits it advertises "may perform destructive updates" to any client
    that reads the field without checking ``readOnlyHint`` first.
    """
    for name, ann in CATEGORIES.items():
        for field in HINT_FIELDS:
            assert getattr(ann, field) is not None, f"{name}.{field} is None"


def test_open_world_is_true_everywhere() -> None:
    """Every tool reaches a FortiGate, so no category may claim otherwise.

    This server has no in-process tool: ``fortigate_list`` opens a socket
    per instance when ``check_health=True``. A future closed-world tool
    must come back to the design doc rather than add a category here.
    """
    for name, ann in CATEGORIES.items():
        assert ann.openWorldHint is True, f"{name} does not advertise an open world"


def test_all_exported_categories_are_in_the_registry() -> None:
    """``CATEGORIES`` must not drift behind the module's public constants."""
    exported = {
        name
        for name in tool_annotations.__all__
        if name != "CATEGORIES"
        and isinstance(getattr(tool_annotations, name), type(READ_ONLY))
    }
    assert exported == set(CATEGORIES), (
        f"exported constants {sorted(exported)} != CATEGORIES keys {sorted(CATEGORIES)}"
    )
    # Registry values must be the constants themselves, not copies.
    assert CATEGORIES["READ_ONLY"] is READ_ONLY
