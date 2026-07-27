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

from typing import Any

import pytest

import tool_annotations
from server import mcp
from tool_annotations import (
    CATEGORIES,
    CREATES,
    DESTRUCTIVE,
    READ_ONLY,
    UNCONSTRAINED,
    UPDATES,
)

#: The four hint fields the MCP spec defines. ``ToolAnnotations`` also has
#: ``title``, which is a display string rather than a safety hint and is
#: deliberately left unset.
HINT_FIELDS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")

#: Every tool that changes FortiGate state, and the category it must
#: carry. Adding a mutating tool means adding it here in the same commit;
#: that is the point of the list. ``monitor_network_ping`` is deliberately
#: absent -- it POSTs but changes nothing on the device.
EXPECTED_MUTATING: dict[str, Any] = {
    # firewall.py
    "firewall_address_create": CREATES,
    "firewall_address_delete": DESTRUCTIVE,
    "firewall_address_update": DESTRUCTIVE,
    "firewall_addrgrp_create": CREATES,
    "firewall_addrgrp_delete": DESTRUCTIVE,
    "firewall_ippool_create": CREATES,
    "firewall_policy_create": CREATES,
    "firewall_policy_delete": DESTRUCTIVE,
    "firewall_policy_move": DESTRUCTIVE,
    "firewall_policy_update": DESTRUCTIVE,
    "firewall_service_create": CREATES,
    "firewall_vip_create": CREATES,
    "firewall_vip_delete": DESTRUCTIVE,
    "monitor_firewall_session_close": DESTRUCTIVE,
    # generic.py
    "cmdb_create": CREATES,
    "cmdb_delete": DESTRUCTIVE,
    "cmdb_update": DESTRUCTIVE,
    "monitor_action": UNCONSTRAINED,
    "service_call": UNCONSTRAINED,
    # log.py
    "log_fortianalyzer_setting_update": DESTRUCTIVE,
    # router.py
    "router_bgp_update": DESTRUCTIVE,
    "router_static_create": CREATES,
    "router_static_delete": DESTRUCTIVE,
    "router_static_update": DESTRUCTIVE,
    # security.py
    "antivirus_profile_create": CREATES,
    "ips_sensor_create": CREATES,
    "ips_sensor_delete": DESTRUCTIVE,
    # system.py
    "system_admin_create": CREATES,
    "system_admin_delete": DESTRUCTIVE,
    "system_dhcp_server_create": CREATES,
    "system_dns_update": DESTRUCTIVE,
    "system_global_update": DESTRUCTIVE,
    "system_interface_create": CREATES,
    "system_interface_delete": DESTRUCTIVE,
    "system_interface_update": DESTRUCTIVE,
    "system_ntp_update": DESTRUCTIVE,
    # user.py
    "monitor_user_disconnect": DESTRUCTIVE,
    "user_group_create": CREATES,
    "user_group_delete": DESTRUCTIVE,
    "user_ldap_create": CREATES,
    "user_local_create": CREATES,
    "user_local_delete": DESTRUCTIVE,
    "user_local_update": DESTRUCTIVE,
    "user_radius_create": CREATES,
    # vpn.py
    "monitor_vpn_ipsec_tunnel_down": DESTRUCTIVE,
    "monitor_vpn_ipsec_tunnel_up": UPDATES,
    "monitor_vpn_ssl_delete_user": DESTRUCTIVE,
    "vpn_ipsec_phase1_create": CREATES,
    "vpn_ipsec_phase1_delete": DESTRUCTIVE,
    "vpn_ipsec_phase1_update": DESTRUCTIVE,
    "vpn_ipsec_phase2_create": CREATES,
    "vpn_ipsec_phase2_delete": DESTRUCTIVE,
    "vpn_ssl_portal_create": CREATES,
    "vpn_ssl_portal_delete": DESTRUCTIVE,
    "vpn_ssl_settings_update": DESTRUCTIVE,
    # wireless.py
    "wifi_vap_create": CREATES,
    "wifi_vap_delete": DESTRUCTIVE,
    "wifi_wtp_deauthorize": DESTRUCTIVE,
}


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


@pytest.fixture(scope="module")
def tools() -> dict[str, Any]:
    """Every registered tool, by name.

    ``server`` validates ``FORTIOS_HOST``/``FORTIOS_API_TOKEN`` only at
    lifespan startup, so importing it here needs no environment and opens
    no connection. This server has no dynamic tool mode, so one import
    reaches the whole surface.
    """
    return {tool.name: tool for tool in mcp._tool_manager.list_tools()}


def test_the_frozen_list_covers_the_whole_write_surface(
    tools: dict[str, Any],
) -> None:
    """Guard the premise of every assertion below.

    A frozen write-surface test proves nothing if the tools never
    registered, so pin the total. ``tests/test_tools_have_instance_param.py``
    pins the same 241 by AST; this pins it at the registry.
    """
    assert len(tools) == 241, f"registered {len(tools)} tools, expected 241"
    assert len(EXPECTED_MUTATING) == 58, (
        f"EXPECTED_MUTATING holds {len(EXPECTED_MUTATING)} names, expected 58"
    )


def test_every_tool_is_annotated(tools: dict[str, Any]) -> None:
    """Catches a new tool added with a bare ``@mcp.tool()``."""
    for name, tool in tools.items():
        ann = tool.annotations
        assert ann is not None, f"{name} has no annotations (bare @mcp.tool()?)"
        for field in HINT_FIELDS:
            assert getattr(ann, field) is not None, f"{name}.{field} is None"


def test_every_tool_uses_an_approved_category(tools: dict[str, Any]) -> None:
    """Hints must match a reviewed category exactly, not merely be plausible."""
    approved = {
        tuple(getattr(ann, field) for field in HINT_FIELDS): name
        for name, ann in CATEGORIES.items()
    }
    for name, tool in tools.items():
        key = tuple(getattr(tool.annotations, field) for field in HINT_FIELDS)
        assert key in approved, (
            f"{name} carries an unapproved hint combination {key}; add a category "
            f"to tool_annotations.CATEGORIES instead of hand-rolling ToolAnnotations"
        )


def test_mutating_set_is_frozen(tools: dict[str, Any]) -> None:
    """The write surface is exactly EXPECTED_MUTATING -- no more, no less."""
    actual = {
        name
        for name, tool in tools.items()
        if tool.annotations.readOnlyHint is not True
    }
    expected = set(EXPECTED_MUTATING)

    unexpected = actual - expected
    assert not unexpected, (
        f"tool(s) {sorted(unexpected)} became non-read-only; if that is intended, "
        f"add them to EXPECTED_MUTATING with a reviewed category"
    )
    missing = expected - actual
    assert not missing, (
        f"tool(s) {sorted(missing)} mutate a FortiGate but no longer advertise it; "
        f"a writer annotated READ_ONLY is the dangerous direction of this bug"
    )


def test_mutating_categories_match(tools: dict[str, Any]) -> None:
    for name, expected in EXPECTED_MUTATING.items():
        assert name in tools, f"{name} is no longer registered"
        assert tools[name].annotations == expected, (
            f"{name}: expected {expected!r}, got {tools[name].annotations!r}"
        )


def test_no_tool_claims_a_closed_world(tools: dict[str, Any]) -> None:
    """Anything that reaches a FortiGate must advertise an open world."""
    closed = sorted(
        name for name, tool in tools.items() if tool.annotations.openWorldHint is False
    )
    assert closed == [], (
        f"tool(s) {closed} claim a closed world; every tool here queries a "
        f"FortiGate and must not claim otherwise"
    )
