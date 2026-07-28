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

EXPECTED_ROW_COUNTS = {
    "firewall": 14,
    "log": 4,
    "monitor": 10,
    "router": 17,
    "security": 27,
    "system": 19,
    "user": 7,
    "vpn": 12,
    "wireless": 11,
}

#: Every ``(api, path)`` pair the table must expose: the 121 read endpoints
#: plus the 15 delete paths, deduplicated (12 of the 15 delete paths repeat a
#: read path already in the set). This is a literal, checked-in oracle
#: external to ``resources.py`` -- generated once from the reviewed table
#: with a throwaway script, not read from it at test time -- so a typo in
#: any row (e.g. ``user/local`` -> ``user/lokal``) changes the *set* the
#: table produces and fails the comparison below, rather than surviving
#: because the completeness check was computed from the same typo'd table.
#: A deliberate, reviewed change to ``resources.py`` must update this
#: literal in the same commit; that edit is the point.
EXPECTED_REACHABLE_ENDPOINTS: frozenset[tuple[str, str]] = frozenset(
    {
        ("cmdb", "antivirus/profile"),
        ("cmdb", "antivirus/settings"),
        ("cmdb", "application/group"),
        ("cmdb", "application/list"),
        ("cmdb", "automation/setting"),
        ("cmdb", "certificate/ca"),
        ("cmdb", "certificate/local"),
        ("cmdb", "dlp/dictionary"),
        ("cmdb", "dlp/filepattern"),
        ("cmdb", "dlp/sensor"),
        ("cmdb", "dnsfilter/domain-filter"),
        ("cmdb", "dnsfilter/profile"),
        ("cmdb", "emailfilter/block-allow-list"),
        ("cmdb", "emailfilter/profile"),
        ("cmdb", "file-filter/profile"),
        ("cmdb", "firewall.schedule/onetime"),
        ("cmdb", "firewall.schedule/recurring"),
        ("cmdb", "firewall.service/custom"),
        ("cmdb", "firewall.service/group"),
        ("cmdb", "firewall/address"),
        ("cmdb", "firewall/addrgrp"),
        ("cmdb", "firewall/central-snat-map"),
        ("cmdb", "firewall/ippool"),
        ("cmdb", "firewall/policy"),
        ("cmdb", "firewall/shaping-policy"),
        ("cmdb", "firewall/ssl-ssh-profile"),
        ("cmdb", "firewall/vip"),
        ("cmdb", "firewall/vipgrp"),
        ("cmdb", "icap/profile"),
        ("cmdb", "icap/server"),
        ("cmdb", "ips/custom"),
        ("cmdb", "ips/sensor"),
        ("cmdb", "log.disk/filter"),
        ("cmdb", "log.disk/setting"),
        ("cmdb", "log.fortianalyzer/setting"),
        ("cmdb", "log.memory/setting"),
        ("cmdb", "log.syslogd/setting"),
        ("cmdb", "router/access-list"),
        ("cmdb", "router/bgp"),
        ("cmdb", "router/community-list"),
        ("cmdb", "router/ospf"),
        ("cmdb", "router/ospf6"),
        ("cmdb", "router/policy"),
        ("cmdb", "router/prefix-list"),
        ("cmdb", "router/rip"),
        ("cmdb", "router/route-map"),
        ("cmdb", "router/static"),
        ("cmdb", "router/static6"),
        ("cmdb", "ssh-filter/profile"),
        ("cmdb", "system.autoupdate/schedule"),
        ("cmdb", "system.dhcp/server"),
        ("cmdb", "system.snmp/community"),
        ("cmdb", "system.snmp/sysinfo"),
        ("cmdb", "system.snmp/user"),
        ("cmdb", "system/admin"),
        ("cmdb", "system/dns"),
        ("cmdb", "system/global"),
        ("cmdb", "system/interface"),
        ("cmdb", "system/ntp"),
        ("cmdb", "system/sdwan"),
        ("cmdb", "system/vdom"),
        ("cmdb", "user/group"),
        ("cmdb", "user/ldap"),
        ("cmdb", "user/local"),
        ("cmdb", "user/radius"),
        ("cmdb", "user/saml"),
        ("cmdb", "user/tacacs+"),
        ("cmdb", "virtual-patch/profile"),
        ("cmdb", "voip/profile"),
        ("cmdb", "vpn.certificate/ca"),
        ("cmdb", "vpn.certificate/local"),
        ("cmdb", "vpn.certificate/ocsp-server"),
        ("cmdb", "vpn.certificate/remote"),
        ("cmdb", "vpn.ipsec/phase1-interface"),
        ("cmdb", "vpn.ipsec/phase2-interface"),
        ("cmdb", "vpn.ssl.web/host-check-software"),
        ("cmdb", "vpn.ssl.web/portal"),
        ("cmdb", "vpn.ssl/settings"),
        ("cmdb", "waf/profile"),
        ("cmdb", "waf/signature"),
        ("cmdb", "webfilter/content"),
        ("cmdb", "webfilter/override"),
        ("cmdb", "webfilter/profile"),
        ("cmdb", "webfilter/urlfilter"),
        ("cmdb", "wireless-controller.hotspot20/hs-profile"),
        ("cmdb", "wireless-controller/qos-profile"),
        ("cmdb", "wireless-controller/setting"),
        ("cmdb", "wireless-controller/vap"),
        ("cmdb", "wireless-controller/vap-group"),
        ("cmdb", "wireless-controller/wtp"),
        ("cmdb", "wireless-controller/wtp-profile"),
        ("cmdb", "ztna/web-proxy"),
        ("monitor", "endpoint-control/summary"),
        ("monitor", "firewall/address-dynamic"),
        ("monitor", "firewall/policy"),
        ("monitor", "ips/anomaly"),
        ("monitor", "license/forticare-resellers"),
        ("monitor", "license/status"),
        ("monitor", "network/arp"),
        ("monitor", "network/lldp/neighbors"),
        ("monitor", "router/ipv4"),
        ("monitor", "router/ipv6"),
        ("monitor", "router/statistics"),
        ("monitor", "switch-controller/managed-switch/status"),
        ("monitor", "system/available-certificates"),
        ("monitor", "system/firmware"),
        ("monitor", "system/ha-statistics"),
        ("monitor", "system/performance/status"),
        ("monitor", "system/resource/usage"),
        ("monitor", "system/running-processes"),
        ("monitor", "system/security-rating/status"),
        ("monitor", "system/status"),
        ("monitor", "system/time"),
        ("monitor", "user/banned"),
        ("monitor", "user/fortitoken"),
        ("monitor", "utm/application-categories"),
        ("monitor", "virtual-wan/health-check"),
        ("monitor", "virtual-wan/members"),
        ("monitor", "vpn/ipsec"),
        ("monitor", "vpn/ssl"),
        ("monitor", "wifi/interfering_ap"),
        ("monitor", "wifi/managed_ap"),
        ("monitor", "wifi/rogue_ap"),
        ("monitor", "wifi/spectrum"),
    }
)


def test_row_counts_are_frozen() -> None:
    """121 read rows across nine domains.

    126 collapsed, less one duplicate, less the four dropped on 2026-07-28
    after live testing against FortiOS 7.6.6: firewall/policy6,
    security/ztna_tag_policy, wireless/rf_analysis and
    monitor/fortiview_top_threat_map all pointed at endpoints that do not
    exist on 7.6.x, and none has an equivalent to repoint at.
    """
    actual = {d: len(rows) for d, rows in READ_RESOURCES.items()}
    assert actual == EXPECTED_ROW_COUNTS
    assert sum(actual.values()) == 121
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
        "user/banned",
        "List IPs and users currently banned by the firewall.",
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
    """The table's endpoints match ``EXPECTED_REACHABLE_ENDPOINTS`` exactly.

    ``EXPECTED_REACHABLE_ENDPOINTS`` is a literal frozen independently of
    ``resources.py`` (generated once from the reviewed table, then committed
    as data), so this is a real external oracle rather than a check the
    table could pass by construction: a typo in *any* row -- not just an
    already-known handful of spot checks -- changes the set the table
    produces and fails one of the two assertions below, in whichever
    direction the typo goes (a path silently dropped, or an unintended one
    introduced).

    121 read endpoints plus the 15 delete paths, deduplicated: 12 of the 15
    delete paths repeat a read path already in the set. The other 3 --
    firewall/address, firewall/policy, system/interface -- do not, because
    their `_get`/`_list` siblings carry real filter logic and were
    deliberately kept outside ``READ_RESOURCES``; those three are reachable
    through the surviving `_list`/`_get` tools instead of a `<domain>_read`
    row. Hence 121 + 3, not 121 + 0.

    ``("cmdb", "firewall/policy")`` and ``("monitor", "firewall/policy")``
    are two different endpoints, not a duplicate: the CMDB one is the
    delete path, the monitor one serves firewall/policy_stats.
    """
    reachable = {
        (row.api, row.path) for rows in READ_RESOURCES.values() for row in rows.values()
    } | {("cmdb", row.path) for row in DELETE_RESOURCES.values()}
    assert len(reachable) == 124

    missing = EXPECTED_REACHABLE_ENDPOINTS - reachable
    assert missing == set(), f"expected endpoint(s) became unreachable: {missing}"
    added = reachable - EXPECTED_REACHABLE_ENDPOINTS
    assert added == set(), f"unexpected endpoint(s) not in the frozen oracle: {added}"


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
