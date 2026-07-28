"""A ratchet on the advertised tool surface.

Every tool's name, description, ``inputSchema`` and ``annotations`` are sent
to the client on every request, before the model does any work. At 241 tools
that was 227,145 characters -- roughly 56,800 tokens -- and 45% of it was the
same two parameter descriptions repeated 241 times.

The 2026-07-28 tool-surface collapse folded 160 pure-alias read/delete tools
into nine ``<domain>_read`` tools plus ``fortios_delete``, cutting that to 91
tools and ~102,400 characters (-55%). ``SURFACE_CEILING_CHARS`` is set to
104,000 -- the design spec's committed ceiling, ~1,600 characters of
headroom above the measured total, room for roughly two more tools before
this number needs to be re-examined rather than nudged.

``SURFACE_CEILING_CHARS`` only ever moves down. Raising it is the signal that
a change made the server more expensive for every client on every request,
which is a decision that belongs in review rather than in a passing test.
"""

from __future__ import annotations

import json

from server import mcp

#: Measured ceiling. Lower this whenever a change shrinks the surface; never
#: raise it without recording why in the commit message.
SURFACE_CEILING_CHARS = 104_000


async def _tool_payloads() -> list[dict[str, object]]:
    """Every registered tool, shaped exactly as ``list_tools()`` emits it."""
    return [
        {
            "name": tool.name,
            "description": tool.description,
            "inputSchema": tool.inputSchema,
            "annotations": (
                tool.annotations.model_dump() if tool.annotations else None
            ),
        }
        for tool in await mcp.list_tools()
    ]


async def serialised_surface_chars() -> int:
    """Total characters the server advertises across all tools."""
    return sum(len(json.dumps(payload)) for payload in await _tool_payloads())


async def test_surface_stays_under_the_ceiling() -> None:
    total = await serialised_surface_chars()
    assert total <= SURFACE_CEILING_CHARS, (
        f"tool surface grew to {total} chars, ceiling is "
        f"{SURFACE_CEILING_CHARS}. Every client pays this on every request."
    )


async def test_ceiling_is_not_slack() -> None:
    """The ceiling tracks reality, so a big win must tighten it."""
    total = await serialised_surface_chars()
    assert total >= SURFACE_CEILING_CHARS - 10_000, (
        f"surface is {total} chars but the ceiling is still "
        f"{SURFACE_CEILING_CHARS} -- tighten it in this commit."
    )
