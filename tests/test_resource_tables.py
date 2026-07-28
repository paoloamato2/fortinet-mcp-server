"""Contracts on the generated resource table.

The table replaced 160 tools. Two things must hold for that to have been
safe: every path those tools could reach is still reachable, and no two rows
claim the same endpoint. The first is migration completeness; the second is
what found that ``system_fortiguard_status`` and ``monitor_license_status``
were the same call.
"""

from __future__ import annotations

from resources import (
    DELETE_RESOURCES,
    READ_RESOURCES,
    SINGLETON_PATHS,
    Resource,
)
from server import mcp

EXPECTED_ROW_COUNTS = {
    "firewall": 15,
    "log": 4,
    "monitor": 11,
    "router": 17,
    "security": 28,
    "system": 19,
    "user": 7,
    "vpn": 12,
    "wireless": 12,
}


def test_row_counts_are_frozen() -> None:
    """125 read rows across nine domains -- 126 collapsed, less one duplicate."""
    actual = {d: len(rows) for d, rows in READ_RESOURCES.items()}
    assert actual == EXPECTED_ROW_COUNTS
    assert sum(actual.values()) == 125
    assert len(DELETE_RESOURCES) == 15


def test_no_two_rows_claim_the_same_endpoint() -> None:
    """A duplicate row means two enum values issue one identical call."""
    seen: dict[tuple[str, str], str] = {}
    clashes: list[str] = []
    for domain, rows in READ_RESOURCES.items():
        for value, row in rows.items():
            key = (row.api, row.path)
            where = f"{domain}/{value}"
            if key in seen:
                clashes.append(f"{key} claimed by {seen[key]} and {where}")
            seen[key] = where
    assert clashes == [], f"duplicate endpoints: {clashes}"


def test_singletons_are_not_keyed_and_tables_are() -> None:
    """``keyed`` follows the path, not per-row judgement."""
    wrong: list[str] = []
    for domain, rows in READ_RESOURCES.items():
        for value, row in rows.items():
            expected = row.api == "cmdb" and row.path not in SINGLETON_PATHS
            if row.keyed is not expected:
                wrong.append(f"{domain}/{value} keyed={row.keyed}, want {expected}")
    assert wrong == [], f"keyed misclassified: {wrong}"


def test_monitor_rows_are_never_keyed() -> None:
    """Monitor endpoints take query parameters, not a path key."""
    keyed_monitors = [
        f"{d}/{v}"
        for d, rows in READ_RESOURCES.items()
        for v, row in rows.items()
        if row.api == "monitor" and row.keyed
    ]
    assert keyed_monitors == []


def test_spot_check_rows_carry_the_original_docstrings() -> None:
    """The summaries are the replaced tools' docstrings, not paraphrases."""
    assert READ_RESOURCES["user"]["local"] == Resource(
        "cmdb", "user/local", "List all local user accounts.", keyed=True
    )
    assert READ_RESOURCES["system"]["global"] == Resource(
        "cmdb",
        "system/global",
        "Get FortiOS global settings (hostname, admin timeout, language, etc.).",
        keyed=False,
    )
    assert READ_RESOURCES["wireless"]["vap"] == Resource(
        "cmdb",
        "wireless-controller/vap",
        "List all VAPs (Virtual APs / SSIDs).",
        keyed=True,
    )
    assert READ_RESOURCES["monitor"]["license_status"] == Resource(
        "monitor",
        "license/status",
        "Get FortiGuard license and subscription status for all services.",
        keyed=False,
    )
    assert READ_RESOURCES["firewall"]["iplist"] == Resource(
        "monitor",
        "firewall/iplist",
        "List active banned/exempt IPs in the firewall.",
        keyed=False,
    )


def test_the_dropped_duplicate_is_absent() -> None:
    """``license/status`` is reachable once, via monitor_read."""
    assert "fortiguard_status" not in READ_RESOURCES["system"]
    paths = [row.path for rows in READ_RESOURCES.values() for row in rows.values()]
    assert paths.count("license/status") == 1


def test_every_summary_is_present_and_terse() -> None:
    """Summaries reach the model, so an empty or essay-length one is a bug."""
    bad = [
        f"{d}/{v}"
        for d, rows in READ_RESOURCES.items()
        for v, row in rows.items()
        if not row.summary.strip() or len(row.summary) > 120
    ]
    assert bad == [], f"summaries empty or over 120 chars: {bad}"


def test_delete_rows_are_all_keyed_cmdb() -> None:
    """Every deletable object is addressed by key on the cmdb API."""
    wrong = [
        v for v, row in DELETE_RESOURCES.items() if row.api != "cmdb" or not row.keyed
    ]
    assert wrong == []


def test_delete_resource_keys_are_domain_qualified() -> None:
    """DELETE_RESOURCES backs one global fortios_delete, unlike the nine
    per-domain read tables -- a bare key like "policy" or "local" would be
    ambiguous across domains, so every key must carry its domain prefix.
    """
    assert set(DELETE_RESOURCES) == {
        "firewall_policy",
        "firewall_address",
        "firewall_addrgrp",
        "firewall_vip",
        "router_static",
        "ips_sensor",
        "system_interface",
        "system_admin",
        "user_local",
        "user_group",
        "vpn_ipsec_phase1",
        "vpn_ipsec_phase2",
        "vpn_ssl_portal",
        "wifi_wtp",
        "wifi_vap",
    }


def test_no_summary_is_truncated() -> None:
    """A summary cut off mid-docstring-wrap leaves unbalanced parentheses
    and no trailing period -- exactly what a naive first-line split does to
    a sentence that wraps onto a second line.
    """
    bad = [
        f"{d}/{v}"
        for d, rows in READ_RESOURCES.items()
        for v, row in rows.items()
        if row.summary.count("(") != row.summary.count(")")
        or not row.summary.endswith(".")
    ]
    bad += [
        v
        for v, row in DELETE_RESOURCES.items()
        if row.summary.count("(") != row.summary.count(")")
        or not row.summary.endswith(".")
    ]
    assert bad == [], f"truncated or unbalanced summaries: {bad}"


def test_migration_completeness_against_the_removed_tools() -> None:
    """Every endpoint the removed tools could reach is still reachable.

    Read from the table rather than the (by now deleted) tool bodies: the
    generator derived these rows from those bodies, and this asserts the
    result covers each path exactly once per API family.
    """
    reachable = {
        (row.api, row.path) for rows in READ_RESOURCES.values() for row in rows.values()
    } | {("cmdb", row.path) for row in DELETE_RESOURCES.values()}
    # 125 read endpoints; 12 of the 15 delete paths duplicate a read path
    # already in the set. The other 3 -- firewall/address, firewall/policy,
    # system/interface -- do not: their _get/_list siblings carry real
    # filter logic and were deliberately kept outside this table (see
    # KEEP_GET in scripts/generate_resources.py), so those three endpoints
    # are reachable through the surviving _list/_get tools instead of a
    # <domain>_read row. Hence 125 + 3, not 125 + 0.
    assert len(reachable) == 128
    for required in (
        ("cmdb", "firewall/addrgrp"),
        ("cmdb", "ips/sensor"),
        ("cmdb", "vpn.ipsec/phase1-interface"),
        ("cmdb", "user/tacacs+"),
        ("monitor", "system/status"),
        ("monitor", "wifi/rogue_ap"),
        ("monitor", "sdwan/health-check"),
        ("cmdb", "log.fortianalyzer/setting"),
    ):
        assert required in reachable, f"{required} became unreachable"


def test_literal_aliases_match_the_table_keys() -> None:
    """A ``Literal`` that drifts from its dict advertises a broken enum."""
    import typing

    import resources

    for domain, alias_name in (
        ("firewall", "FirewallResource"),
        ("log", "LogResource"),
        ("monitor", "MonitorResource"),
        ("router", "RouterResource"),
        ("security", "SecurityResource"),
        ("system", "SystemResource"),
        ("user", "UserResource"),
        ("vpn", "VpnResource"),
        ("wireless", "WirelessResource"),
    ):
        alias = getattr(resources, alias_name)
        assert set(typing.get_args(alias)) == set(READ_RESOURCES[domain]), (
            f"{alias_name} drifted from READ_RESOURCES[{domain!r}]"
        )
    assert set(typing.get_args(resources.DeletableResource)) == set(DELETE_RESOURCES)


async def test_the_table_does_not_change_the_surface_yet() -> None:
    """This task adds data only -- no tool is added or removed."""
    tools = await mcp.list_tools()
    assert len(tools) == 241
