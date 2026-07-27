"""MCP tool annotation categories (spec ``ToolAnnotations``).

Every registered tool declares one of the constants below via
``@mcp.tool(annotations=...)``. Annotations are advertisement only -- they
change nothing about how a tool runs, they tell a client what a call is
going to do so it can decide what to auto-approve, what to confirm and
what to surface. A wrong hint is therefore a safety bug, not a cosmetic
one, and ``tests/test_tool_annotations.py`` freezes the classification.

This module sits at package top level next to ``instances.py`` and
``fortios_client.py``, matching the flat layout. It imports nothing from
the project, so ``server.py`` and every module under ``tools/`` can reach
it with no cycle and no side effect.

All four hint fields are set explicitly on every category, including the
two the spec calls meaningful "only when ``readOnlyHint`` is false".
``destructiveHint`` **defaults to true** on the wire, so omitting it on a
reader means a client that reads that field without first checking
``readOnlyHint`` sees "may perform destructive updates" on
``system_status``. Explicit ``False`` costs one line and can only narrow
what a client believes a reader might do.

Where the read-only line falls (recorded in full, with the six boundary
calls, in ``docs/superpowers/specs/2026-07-27-mcp-tool-annotations-design.md``):
a tool is read-only when a call leaves both the FortiGate's stored
configuration *and* its live session state as it found them. Two
consequences worth stating outright:

- **HTTP verb does not decide it.** ``monitor_network_ping`` POSTs and is
  ``READ_ONLY`` -- it emits ICMP and returns timings, changing nothing on
  the device. ``wifi_wtp_deauthorize`` reads operational and is
  ``DESTRUCTIVE`` -- it is a ``cmdb_delete`` that removes the WTP entry.
- **Live state counts as state.** Closing sessions or dropping a tunnel
  changes no stored config, but the dropped sessions are unrecoverable,
  so those tools are ``DESTRUCTIVE`` rather than ``UPDATES``.
"""

from mcp.types import ToolAnnotations

#: Reads a FortiGate and changes nothing on it. The default for this
#: server: 183 of 241 tools, every ``*_list``/``*_get``/``*_status``, all
#: 16 ``log_*`` tools, ``monitor_system_config_backup``,
#: ``monitor_network_ping`` and ``fortigate_list``.
READ_ONLY = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)

#: Adds new configuration to a FortiGate (``cmdb_post``). Additive, so not
#: destructive; a repeat call adds a second object or fails on a duplicate
#: key, so not idempotent.
CREATES = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=True,
)

#: Flips reversible operational state without tearing anything down. Not
#: destructive because nothing is lost, and idempotent because repeating
#: it is a no-op. Exactly one member -- ``monitor_vpn_ipsec_tunnel_up``,
#: the twin of ``monitor_vpn_ipsec_tunnel_down``.
UPDATES = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)

#: Removes FortiGate state, or replaces it with no recovery path. Deletes
#: obviously; also every ``cmdb_put``, because FortiOS PUT is full-object
#: replacement and the prior value is unrecoverable afterwards, which is
#: what "destructive update" means in the spec as opposed to "additive
#: only"; also ``firewall_policy_move``, because policy order is the
#: firewall's semantics and the call carries no way back; also the four
#: teardown actions, whose dropped sessions do not come back.
DESTRUCTIVE = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=True,
    openWorldHint=True,
)

#: Dispatches to a caller-chosen endpoint, so the hints must be the union
#: of everything reachable. ``monitor_action`` reaches
#: ``system/os/reboot``; ``service_call(method="POST")`` reaches
#: ``sniffer/start``. Inheriting ``READ_ONLY`` here would be the single
#: most misleading annotation in the server: one tool advertising "changes
#: nothing" while exposing every mutating endpoint behind a string.
UNCONSTRAINED = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=True,
)

#: Every approved category, by name. The annotation contract test asserts
#: each registered tool's annotations equal one of these, so a new tool
#: cannot introduce an unreviewed hint combination by hand.
CATEGORIES: dict[str, ToolAnnotations] = {
    "READ_ONLY": READ_ONLY,
    "CREATES": CREATES,
    "UPDATES": UPDATES,
    "DESTRUCTIVE": DESTRUCTIVE,
    "UNCONSTRAINED": UNCONSTRAINED,
}

__all__ = [
    "CATEGORIES",
    "CREATES",
    "DESTRUCTIVE",
    "READ_ONLY",
    "UNCONSTRAINED",
    "UPDATES",
]
