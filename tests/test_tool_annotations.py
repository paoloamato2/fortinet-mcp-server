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

import ast
from pathlib import Path
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

TOOLS_DIR = Path(__file__).resolve().parent.parent / "tools"

#: The six ``FortiOSClient`` methods that mutate a FortiGate's stored
#: configuration or its live session state -- the same six named in
#: ``fortios_client.py`` and in the design doc's "Enabling constraint".
WRITE_METHODS = frozenset(
    {
        "cmdb_post",
        "cmdb_put",
        "cmdb_delete",
        "monitor_post",
        "log_post",
        "service_post",
    }
)

#: Tools whose body calls a write method but change nothing on the device.
#: ``monitor_network_ping`` POSTs to ``network/diag-icmp-ping`` and returns
#: ICMP timings; nothing on the FortiGate is created, replaced, or torn
#: down, so it is exempt from the "reaches a write method => must not
#: advertise readOnlyHint=True" rule enforced below. A set rather than an
#: inline skip, mirroring ``MODULES_WITHOUT_INSTANCE_PARAM`` in
#: ``tests/test_tools_have_instance_param.py`` -- its own test pins it shut
#: so a second exemption cannot be added without review.
POSTS_WITHOUT_MUTATING = {"monitor_network_ping"}

#: Registered tool count. Two contracts below assert against it, so the
#: collapse moves this one line per task rather than hunting literals:
#: 241 -> 232 (user_read) -> 105 (the other eight) -> 91 (fortios_delete).
EXPECTED_TOOL_COUNT = 232


def _tool_functions(path: Path) -> list[ast.AsyncFunctionDef | ast.FunctionDef]:
    """Every function in ``path`` registered as an MCP tool.

    Most tools use ``@mcp.tool(...)`` decorator syntax. A tool whose
    description is built at runtime (a generated resource table appended to
    ``__doc__``) cannot use it -- a docstring must be a literal -- so it is
    defined undecorated and registered by an explicit ``mcp.tool(...)(name)``
    call instead (see ``user_read`` in ``tools/user.py``). This counts both
    forms, so the guards below still see a tool registered the second way.

    Duplicates the helper of the same name in
    ``tests/test_tools_have_instance_param.py`` rather than importing it, so
    this file's behaviour guard does not depend on that file's internals.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    by_name: dict[str, ast.AsyncFunctionDef | ast.FunctionDef] = {}
    decorated: list[ast.AsyncFunctionDef | ast.FunctionDef] = []
    registered_by_call: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            by_name[node.name] = node
            if any("mcp.tool" in ast.unparse(d) for d in node.decorator_list):
                decorated.append(node)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Call)
            and "mcp.tool" in ast.unparse(node.func)
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Name)
        ):
            registered_by_call.add(node.args[0].id)

    decorated_names = {fn.name for fn in decorated}
    found = list(decorated)
    found.extend(
        by_name[name]
        for name in sorted(registered_by_call)
        if name in by_name and name not in decorated_names
    )
    return found


def _tool_modules() -> list[Path]:
    return sorted(p for p in TOOLS_DIR.glob("*.py") if p.name != "__init__.py")


def _write_methods_reached(
    fn: ast.AsyncFunctionDef | ast.FunctionDef,
) -> set[str]:
    """The ``WRITE_METHODS`` reached via a ``client.<attr>(...)`` call in ``fn``.

    Every tool resolves its client into a local variable literally named
    ``client`` (the convention documented in ``CLAUDE.md``: ``client:
    FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(...)``),
    so matching ``ast.Attribute`` nodes whose value is the name ``client``
    finds every write call a tool body makes, including ones nested in an
    ``if``/``try`` branch.
    """
    reached: set[str] = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.Attribute):
            continue
        if node.attr in WRITE_METHODS and (
            isinstance(node.value, ast.Name) and node.value.id == "client"
        ):
            reached.add(node.attr)
    return reached


def _tool_write_methods() -> dict[str, set[str]]:
    """Map every ``@mcp.tool`` function name in ``tools/*.py`` to the write
    methods its body reaches (the empty set for a pure reader)."""
    result: dict[str, set[str]] = {}
    for path in _tool_modules():
        for fn in _tool_functions(path):
            result[fn.name] = _write_methods_reached(fn)
    return result


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


def test_categories_registry_has_exactly_five_entries() -> None:
    """A sixth category is a reviewed design change, not a spare constant.

    ``test_mutating_set_is_frozen`` keys off ``readOnlyHint is not True``, so
    a new category that still sets ``readOnlyHint=True`` (however it differs
    on the other three hints) would never appear in that test's ``actual``
    set and so would never be checked against ``EXPECTED_MUTATING``. Pinning
    the count means a sixth category requires updating this file, not only
    ``tool_annotations.py``.
    """
    assert len(CATEGORIES) == 5


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
    assert len(tools) == EXPECTED_TOOL_COUNT, (
        f"registered {len(tools)} tools, expected {EXPECTED_TOOL_COUNT}"
    )
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


def test_every_category_has_at_least_one_tool(tools: dict[str, Any]) -> None:
    """``CATEGORIES`` is a registry of *used* classifications, not a menu.

    An orphan category -- pairwise-distinct, all four hints set, open-world
    -- would pass every other contract in this file silently, since none of
    them check that a category is actually carried by a registered tool.
    """
    used = {
        tuple(getattr(tool.annotations, field) for field in HINT_FIELDS)
        for tool in tools.values()
        if tool.annotations is not None
    }
    for name, ann in CATEGORIES.items():
        key = tuple(getattr(ann, field) for field in HINT_FIELDS)
        assert key in used, f"{name} is registered but no tool carries it"


def test_every_tool_uses_an_approved_category(tools: dict[str, Any]) -> None:
    """Hints must match a reviewed category exactly, not merely be plausible."""
    approved = {
        tuple(getattr(ann, field) for field in HINT_FIELDS): name
        for name, ann in CATEGORIES.items()
    }
    for name, tool in tools.items():
        if tool.annotations is None:
            continue  # test_every_tool_is_annotated owns this failure
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
        if tool.annotations is not None and tool.annotations.readOnlyHint is not True
        # tool.annotations is None is test_every_tool_is_annotated's failure to own
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
        name
        for name, tool in tools.items()
        if tool.annotations is not None and tool.annotations.openWorldHint is False
        # tool.annotations is None is test_every_tool_is_annotated's failure to own
    )
    assert closed == [], (
        f"tool(s) {closed} claim a closed world; every tool here queries a "
        f"FortiGate and must not claim otherwise"
    )


def test_the_posting_reader_exemption_has_not_grown() -> None:
    """Mirrors ``test_the_exemption_list_has_not_grown`` in
    ``tests/test_tools_have_instance_param.py``: a second name here must be
    a reviewed decision, not a silent addition.
    """
    assert POSTS_WITHOUT_MUTATING == {"monitor_network_ping"}


def test_the_ast_walk_covers_every_registered_tool() -> None:
    """Guards the two behaviour-derived tests below against passing
    vacuously because the AST walk matched nothing."""
    by_name = _tool_write_methods()
    assert len(by_name) == EXPECTED_TOOL_COUNT, (
        f"AST walk found {len(by_name)} tools, expected {EXPECTED_TOOL_COUNT}"
    )


def test_reaching_a_write_method_forbids_a_read_only_hint(
    tools: dict[str, Any],
) -> None:
    """The behaviour guard the contracts above cannot provide.

    Every contract above reads ``tool.annotations`` and nothing else -- none
    of them read what a tool's body actually does. Flip a reader's
    ``client.monitor_get(...)`` to ``client.monitor_post(...)`` and every
    contract above still passes, because the annotation on the decorator
    never changed. This test re-derives the write surface from the AST (the
    same derivation ``EXPECTED_MUTATING`` was built from) and cross-checks
    it against the registered annotations, so a reader that silently starts
    calling a write method is caught here instead of relying on reviewer
    attention.
    """
    by_name = _tool_write_methods()
    non_exempt_writers = {
        name: methods
        for name, methods in by_name.items()
        if methods and name not in POSTS_WITHOUT_MUTATING
    }
    assert non_exempt_writers, (
        "AST walk over tools/*.py found no non-exempt tool reaching a write "
        "method; this guard would otherwise pass vacuously"
    )
    for name, methods in non_exempt_writers.items():
        tool = tools.get(name)
        assert tool is not None, (
            f"{name} calls client.{sorted(methods)[0]} but is not registered"
        )
        assert tool.annotations is not None, (
            f"{name} calls client.{sorted(methods)[0]} (a write method) but has "
            f"no annotations at all"
        )
        assert tool.annotations.readOnlyHint is not True, (
            f"{name} calls client.{sorted(methods)[0]} (a write method) but is "
            f"annotated readOnlyHint=True"
        )


def test_expected_mutating_entries_reach_a_write_method() -> None:
    """The converse of the frozen-list contract: catches a stale entry.

    Every name in ``EXPECTED_MUTATING`` should be a tool whose body reaches
    a write method. If a listed tool is renamed, deleted, or refactored to
    no longer call one, this fails instead of leaving a name in the frozen
    list that no longer means anything.
    """
    by_name = _tool_write_methods()
    for name in EXPECTED_MUTATING:
        assert name in by_name, (
            f"{name} is in EXPECTED_MUTATING but no @mcp.tool function of "
            f"that name exists in tools/*.py"
        )
        assert by_name[name], (
            f"{name} is in EXPECTED_MUTATING but its body reaches no write "
            f"method ({sorted(WRITE_METHODS)}); the entry may be stale"
        )
