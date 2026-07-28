"""Shared parameter definitions for every MCP tool.

``instance`` and ``vdom`` appear on nearly every tool in this server. Inlined,
their descriptions were 103,144 of the 227,145 characters the server
advertised -- 45.4% of the surface spent restating two sentences 241 times,
to a client that has already read ``server.py``'s ``instructions`` block.

The descriptions here are deliberately terse for that reason: the roster of
configured FortiGates, what ``instance="*"`` means and when to use it are all
covered once in the server instructions. This module imports nothing from the
project, so ``tools/*`` and ``server.py`` can both use it with no cycle.
"""

from __future__ import annotations

from typing import Annotated, TypeAlias

from pydantic import Field

#: Which configured FortiGate to talk to. Full roster and the ``"*"`` fan-out
#: semantics are in ``server.py``'s ``instructions``.
InstanceParam: TypeAlias = Annotated[
    str | None,
    Field(default=None, description="FortiGate name; '*'=all. See fortigate_list."),
]

#: Which VDOM to target. Defaults to the client's configured VDOM.
VdomParam: TypeAlias = Annotated[
    str | None,
    Field(default=None, description="VDOM name; '*'=all VDOMs."),
]
