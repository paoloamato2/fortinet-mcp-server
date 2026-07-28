"""The FortiOS resource table behind the per-domain read tools.

Each row is one FortiOS endpoint: which API family serves it, its path, a
one-line summary shown to the model, and whether it accepts a per-object key.
Nine ``<domain>_read`` tools and ``fortios_delete`` dispatch through these
rows, replacing 160 tools whose bodies were a single client call with a
hardcoded path.

Derived by AST from the 160 alias tools this table replaced -- the summaries
are those tools' docstrings, carried over verbatim. The generator was a
one-shot and was retired immediately afterwards: it cannot re-derive rows for
tools that no longer exist. See the commit that added this file for the
derivation. Add a resource by editing this file directly.

Imports nothing from this project, so every layer can use it with no cycle.
"""

from __future__ import annotations

from typing import Literal, NamedTuple, TypeAlias


class Resource(NamedTuple):
    """One readable FortiOS endpoint."""

    api: Literal["cmdb", "monitor"]
    path: str
    summary: str
    keyed: bool = False


SINGLETON_PATHS: frozenset[str] = frozenset(
    {
        "antivirus/settings",
        "automation/setting",
        "log.disk/filter",
        "log.disk/setting",
        "log.fortianalyzer/setting",
        "log.memory/setting",
        "log.syslogd/setting",
        "router/bgp",
        "router/ospf",
        "router/ospf6",
        "router/rip",
        "system.autoupdate/schedule",
        "system.snmp/sysinfo",
        "system/dns",
        "system/global",
        "system/ntp",
        "system/sdwan",
        "system/time",
        "vpn.ssl/settings",
        "wireless-controller/rf-analysis",
        "wireless-controller/setting",
    }
)


FirewallResource: TypeAlias = Literal[
    "address_dynamic",
    "addrgrp",
    "central_snat",
    "iplist",
    "ippool",
    "policy6",
    "policy_stats",
    "schedule_one_time",
    "schedule_recurring",
    "service",
    "service_grp",
    "shaping_policy",
    "ssl_ssh_profile",
    "vip",
    "vipgrp",
]

LogResource: TypeAlias = Literal[
    "disk_filter",
    "disk_setting",
    "fortianalyzer_setting",
    "memory_setting",
]

MonitorResource: TypeAlias = Literal[
    "endpoint_summary",
    "fortiview_top_threat_map",
    "ips_anomaly",
    "license_forticare_resellers",
    "license_status",
    "network_arp",
    "network_lldp_neighbors",
    "security_rating_summary",
    "switch_controller_managed_switch",
    "system_process",
    "utm_app_categories",
]

RouterResource: TypeAlias = Literal[
    "access_list",
    "bgp",
    "community_list",
    "ipv4",
    "ipv6",
    "ospf",
    "ospf6",
    "policy",
    "prefix_list",
    "rip",
    "route_map",
    "sdwan",
    "sdwan_health_check",
    "sdwan_members",
    "static",
    "static6",
    "statistics",
]

SecurityResource: TypeAlias = Literal[
    "antivirus_profile",
    "antivirus_settings",
    "application_group",
    "application_list_profiles",
    "automation_setting",
    "dlp_dictionary",
    "dlp_filepattern",
    "dlp_sensor",
    "dnsfilter_domain_filter",
    "dnsfilter_profile",
    "emailfilter_bwl",
    "emailfilter_profile",
    "file_filter_profile",
    "icap_profile",
    "icap_server",
    "ips_custom",
    "ips_sensor",
    "ssh_filter_profile",
    "virtual_patch_profile",
    "voip_profile",
    "waf_profile",
    "waf_signature",
    "webfilter_content",
    "webfilter_override",
    "webfilter_profile",
    "webfilter_urlfilter",
    "ztna_server",
    "ztna_tag_policy",
]

SystemResource: TypeAlias = Literal[
    "admin",
    "autoupdate_schedule",
    "certificate_ca",
    "certificate_local",
    "dhcp_server",
    "dns",
    "firmware",
    "global",
    "ha_status",
    "log_syslogd",
    "ntp",
    "performance_status",
    "resource_usage",
    "snmp_community",
    "snmp_sysinfo",
    "snmp_user",
    "status",
    "time",
    "vdom",
]

UserResource: TypeAlias = Literal[
    "fortitoken",
    "group",
    "ldap",
    "local",
    "radius",
    "saml",
    "tacacs",
]

VpnResource: TypeAlias = Literal[
    "certificate_ca",
    "certificate_local",
    "certificate_ocsp_server",
    "certificate_remote",
    "certificate_valid",
    "ipsec",
    "ipsec_phase1",
    "ipsec_phase2",
    "ssl",
    "ssl_portal",
    "ssl_settings",
    "ssl_web_host_check_software",
]

WirelessResource: TypeAlias = Literal[
    "controller_setting",
    "hotspot20_profile",
    "interfering_ap",
    "managed_ap",
    "qos_profile",
    "rf_analysis",
    "rogue_ap",
    "spectrum_analysis",
    "vap",
    "vap_group",
    "wtp",
    "wtp_profile",
]

DeletableResource: TypeAlias = Literal[
    "firewall_address",
    "firewall_addrgrp",
    "firewall_policy",
    "firewall_vip",
    "ips_sensor",
    "router_static",
    "system_admin",
    "system_interface",
    "user_group",
    "user_local",
    "vpn_ipsec_phase1",
    "vpn_ipsec_phase2",
    "vpn_ssl_portal",
    "wifi_vap",
    "wifi_wtp",
]


READ_RESOURCES: dict[str, dict[str, Resource]] = {
    "firewall": {
        "address_dynamic": Resource(
            "monitor",
            "firewall/address-dynamic",
            "Get resolved IPs for all dynamic/FQDN firewall address objects.",
            keyed=False,
        ),
        "addrgrp": Resource(
            "cmdb",
            "firewall/addrgrp",
            "List all IPv4 firewall address groups.",
            keyed=True,
        ),
        "central_snat": Resource(
            "cmdb",
            "firewall/central-snat-map",
            "List all central SNAT (outgoing NAT) rules.",
            keyed=True,
        ),
        "iplist": Resource(
            "monitor",
            "firewall/iplist",
            "List active banned/exempt IPs in the firewall.",
            keyed=False,
        ),
        "ippool": Resource(
            "cmdb",
            "firewall/ippool",
            "List all IP pool (source NAT) objects.",
            keyed=True,
        ),
        "policy6": Resource(
            "cmdb", "firewall/policy6", "List all IPv6 firewall policies.", keyed=True
        ),
        "policy_stats": Resource(
            "monitor",
            "firewall/policy-lookup",
            "Get hit counts, bytes, and packet statistics per firewall policy.",
            keyed=False,
        ),
        "schedule_one_time": Resource(
            "cmdb",
            "firewall.schedule/onetime",
            "List all one-time schedules.",
            keyed=True,
        ),
        "schedule_recurring": Resource(
            "cmdb",
            "firewall.schedule/recurring",
            "List all recurring schedules.",
            keyed=True,
        ),
        "service": Resource(
            "cmdb",
            "firewall.service/custom",
            "List all custom firewall service objects.",
            keyed=True,
        ),
        "service_grp": Resource(
            "cmdb",
            "firewall.service/group",
            "List all firewall service groups.",
            keyed=True,
        ),
        "shaping_policy": Resource(
            "cmdb",
            "firewall/shaping-policy",
            "List all traffic shaping policies.",
            keyed=True,
        ),
        "ssl_ssh_profile": Resource(
            "cmdb",
            "firewall/ssl-ssh-profile",
            "List all SSL/SSH deep inspection profiles.",
            keyed=True,
        ),
        "vip": Resource(
            "cmdb", "firewall/vip", "List all Virtual IP (DNAT) objects.", keyed=True
        ),
        "vipgrp": Resource(
            "cmdb", "firewall/vipgrp", "List all VIP groups.", keyed=True
        ),
    },
    "log": {
        "disk_filter": Resource(
            "cmdb",
            "log.disk/filter",
            "Get the disk log filter settings (which log types are enabled).",
            keyed=False,
        ),
        "disk_setting": Resource(
            "cmdb",
            "log.disk/setting",
            "Get the disk logging settings (log level, max log size, etc.).",
            keyed=False,
        ),
        "fortianalyzer_setting": Resource(
            "cmdb",
            "log.fortianalyzer/setting",
            "Get FortiAnalyzer logging configuration (server, port, status).",
            keyed=False,
        ),
        "memory_setting": Resource(
            "cmdb",
            "log.memory/setting",
            "Get the memory logging settings.",
            keyed=False,
        ),
    },
    "monitor": {
        "endpoint_summary": Resource(
            "monitor",
            "endpoint-control/summary",
            "Get endpoint control (FortiClient) summary statistics.",
            keyed=False,
        ),
        "fortiview_top_threat_map": Resource(
            "monitor",
            "fortiview/statistics",
            "Get FortiView threat map data (geo-blocking source countries).",
            keyed=False,
        ),
        "ips_anomaly": Resource(
            "monitor",
            "ips/anomaly",
            "Get IPS anomaly detection statistics.",
            keyed=False,
        ),
        "license_forticare_resellers": Resource(
            "monitor",
            "license/forticare-resellers",
            "Get FortiCare reseller and support contract information.",
            keyed=False,
        ),
        "license_status": Resource(
            "monitor",
            "license/status",
            "Get FortiGuard license and subscription status for all services.",
            keyed=False,
        ),
        "network_arp": Resource(
            "monitor",
            "network/arp",
            "Get the ARP table (IP-to-MAC address mappings).",
            keyed=False,
        ),
        "network_lldp_neighbors": Resource(
            "monitor",
            "network/lldp/neighbors",
            "Get LLDP neighbor information discovered on all interfaces.",
            keyed=False,
        ),
        "security_rating_summary": Resource(
            "monitor",
            "system/security-rating",
            "Get the Security Rating summary score and findings.",
            keyed=False,
        ),
        "switch_controller_managed_switch": Resource(
            "monitor",
            "switch-controller/managed-switch",
            "Get status of all FortiSwitch managed switches.",
            keyed=False,
        ),
        "system_process": Resource(
            "monitor",
            "system/running-processes",
            "List running FortiOS processes with CPU and memory usage.",
            keyed=False,
        ),
        "utm_app_categories": Resource(
            "monitor",
            "utm/app-lookup",
            "Get UTM application category statistics.",
            keyed=False,
        ),
    },
    "router": {
        "access_list": Resource(
            "cmdb",
            "router/access-list",
            "List all router access lists (ACL for routing).",
            keyed=True,
        ),
        "bgp": Resource(
            "cmdb",
            "router/bgp",
            "Get BGP routing configuration (ASN, peers, networks, redistribute).",
            keyed=False,
        ),
        "community_list": Resource(
            "cmdb", "router/community-list", "List all BGP community lists.", keyed=True
        ),
        "ipv4": Resource(
            "monitor",
            "router/ipv4",
            "Get the active IPv4 routing table (all routes in the FIB).",
            keyed=False,
        ),
        "ipv6": Resource(
            "monitor", "router/ipv6", "Get the active IPv6 routing table.", keyed=False
        ),
        "ospf": Resource(
            "cmdb",
            "router/ospf",
            "Get OSPF routing configuration (areas, networks, neighbors, redistribute).",
            keyed=False,
        ),
        "ospf6": Resource(
            "cmdb",
            "router/ospf6",
            "Get OSPFv3 (IPv6) routing configuration.",
            keyed=False,
        ),
        "policy": Resource(
            "cmdb", "router/policy", "List all policy-based routing rules.", keyed=True
        ),
        "prefix_list": Resource(
            "cmdb",
            "router/prefix-list",
            "List all IPv4 prefix lists (used in route filtering).",
            keyed=True,
        ),
        "rip": Resource(
            "cmdb", "router/rip", "Get RIPv1/v2 routing configuration.", keyed=False
        ),
        "route_map": Resource(
            "cmdb",
            "router/route-map",
            "List all route-maps (used for route filtering and attribute modification).",
            keyed=True,
        ),
        "sdwan": Resource(
            "cmdb",
            "system/sdwan",
            "Get the SD-WAN (virtual-WAN) configuration.",
            keyed=False,
        ),
        "sdwan_health_check": Resource(
            "monitor",
            "sdwan/health-check",
            "Get SD-WAN performance SLA health check results.",
            keyed=False,
        ),
        "sdwan_members": Resource(
            "monitor",
            "sdwan/members",
            "Get SD-WAN member interface status and bandwidth usage.",
            keyed=False,
        ),
        "static": Resource(
            "cmdb", "router/static", "List all IPv4 static routes.", keyed=True
        ),
        "static6": Resource(
            "cmdb", "router/static6", "List all IPv6 static routes.", keyed=True
        ),
        "statistics": Resource(
            "monitor",
            "router/statistics",
            "Get routing protocol statistics (BGP, OSPF, RIP adjacencies/neighbors).",
            keyed=False,
        ),
    },
    "security": {
        "antivirus_profile": Resource(
            "cmdb", "antivirus/profile", "List all antivirus profiles.", keyed=True
        ),
        "antivirus_settings": Resource(
            "cmdb",
            "antivirus/settings",
            "Get antivirus engine settings (scan cache, exclusions).",
            keyed=False,
        ),
        "application_group": Resource(
            "cmdb", "application/group", "List all application groups.", keyed=True
        ),
        "application_list_profiles": Resource(
            "cmdb",
            "application/list",
            "List all Application Control profiles.",
            keyed=True,
        ),
        "automation_setting": Resource(
            "cmdb", "automation/setting", "Get global automation settings.", keyed=False
        ),
        "dlp_dictionary": Resource(
            "cmdb", "dlp/dictionary", "List all DLP data dictionaries.", keyed=True
        ),
        "dlp_filepattern": Resource(
            "cmdb", "dlp/filepattern", "List all DLP file pattern tables.", keyed=True
        ),
        "dlp_sensor": Resource(
            "cmdb", "dlp/sensor", "List all DLP sensors.", keyed=True
        ),
        "dnsfilter_domain_filter": Resource(
            "cmdb",
            "dnsfilter/domain-filter",
            "List DNS domain filter tables (custom domain block/allow).",
            keyed=True,
        ),
        "dnsfilter_profile": Resource(
            "cmdb", "dnsfilter/profile", "List all DNS filter profiles.", keyed=True
        ),
        "emailfilter_bwl": Resource(
            "cmdb",
            "emailfilter/bwl",
            "List email filter block/allow lists.",
            keyed=True,
        ),
        "emailfilter_profile": Resource(
            "cmdb", "emailfilter/profile", "List all email filter profiles.", keyed=True
        ),
        "file_filter_profile": Resource(
            "cmdb", "file-filter/profile", "List all file filter profiles.", keyed=True
        ),
        "icap_profile": Resource(
            "cmdb", "icap/profile", "List all ICAP profiles.", keyed=True
        ),
        "icap_server": Resource(
            "cmdb", "icap/server", "List all ICAP server configurations.", keyed=True
        ),
        "ips_custom": Resource(
            "cmdb", "ips/custom", "List all custom IPS signatures.", keyed=True
        ),
        "ips_sensor": Resource(
            "cmdb", "ips/sensor", "List all IPS sensor profiles.", keyed=True
        ),
        "ssh_filter_profile": Resource(
            "cmdb", "ssh-filter/profile", "List all SSH filter profiles.", keyed=True
        ),
        "virtual_patch_profile": Resource(
            "cmdb",
            "virtual-patch/profile",
            "List all Virtual Patch profiles (inline IPS pre-patching).",
            keyed=True,
        ),
        "voip_profile": Resource(
            "cmdb",
            "voip/profile",
            "List all VoIP (SIP/SCCP) inspection profiles.",
            keyed=True,
        ),
        "waf_profile": Resource(
            "cmdb", "waf/profile", "List all WAF profiles.", keyed=True
        ),
        "waf_signature": Resource(
            "cmdb",
            "waf/signature",
            "List all WAF signature configurations.",
            keyed=True,
        ),
        "webfilter_content": Resource(
            "cmdb",
            "webfilter/content",
            "List all web content filter (keyword) tables.",
            keyed=True,
        ),
        "webfilter_override": Resource(
            "cmdb",
            "webfilter/override",
            "List all web filter category override rules.",
            keyed=True,
        ),
        "webfilter_profile": Resource(
            "cmdb", "webfilter/profile", "List all web filter profiles.", keyed=True
        ),
        "webfilter_urlfilter": Resource(
            "cmdb",
            "webfilter/urlfilter",
            "List all URL filter tables (custom URL block/allow lists).",
            keyed=True,
        ),
        "ztna_server": Resource(
            "cmdb",
            "ztna/proxy",
            "List all ZTNA access proxy (application gateway) servers.",
            keyed=True,
        ),
        "ztna_tag_policy": Resource(
            "cmdb",
            "ztna/ems-tag",
            "List all ZTNA EMS tag (posture check) policies.",
            keyed=True,
        ),
    },
    "system": {
        "admin": Resource(
            "cmdb", "system/admin", "List all administrator accounts.", keyed=True
        ),
        "autoupdate_schedule": Resource(
            "cmdb",
            "system.autoupdate/schedule",
            "Get the FortiGuard auto-update schedule.",
            keyed=False,
        ),
        "certificate_ca": Resource(
            "cmdb", "certificate/ca", "List trusted CA certificates.", keyed=True
        ),
        "certificate_local": Resource(
            "cmdb", "certificate/local", "List local (device) certificates.", keyed=True
        ),
        "dhcp_server": Resource(
            "cmdb", "system.dhcp/server", "List all DHCP server instances.", keyed=True
        ),
        "dns": Resource(
            "cmdb",
            "system/dns",
            "Get DNS server configuration (primary, secondary, search domains).",
            keyed=False,
        ),
        "firmware": Resource(
            "monitor",
            "system/firmware",
            "List available firmware versions for upgrade.",
            keyed=False,
        ),
        "global": Resource(
            "cmdb",
            "system/global",
            "Get FortiOS global settings (hostname, admin timeout, language, etc.).",
            keyed=False,
        ),
        "ha_status": Resource(
            "monitor",
            "system/ha-statistics",
            "Get High Availability (HA) cluster status.",
            keyed=False,
        ),
        "log_syslogd": Resource(
            "cmdb",
            "log.syslogd/setting",
            "Get the primary Syslog server configuration.",
            keyed=False,
        ),
        "ntp": Resource(
            "cmdb", "system/ntp", "Get NTP synchronization configuration.", keyed=False
        ),
        "performance_status": Resource(
            "monitor",
            "system/performance/status",
            "Get performance statistics (CPU usage per core, memory, network throughput).",
            keyed=False,
        ),
        "resource_usage": Resource(
            "monitor",
            "system/resource/usage",
            "Get real-time resource usage: CPU, memory, disk, sessions.",
            keyed=False,
        ),
        "snmp_community": Resource(
            "cmdb", "system.snmp/community", "List SNMP v1/v2c communities.", keyed=True
        ),
        "snmp_sysinfo": Resource(
            "cmdb",
            "system.snmp/sysinfo",
            "Get SNMP system info (contact, location, description, trap thresholds).",
            keyed=False,
        ),
        "snmp_user": Resource(
            "cmdb", "system.snmp/user", "List SNMPv3 users.", keyed=True
        ),
        "status": Resource(
            "monitor",
            "system/status",
            "Get the FortiOS system status (firmware version, hostname, serial number, uptime, HA state, etc.).",
            keyed=False,
        ),
        "time": Resource(
            "cmdb",
            "system/time",
            "Get the current system time and timezone.",
            keyed=False,
        ),
        "vdom": Resource(
            "cmdb", "system/vdom", "List all configured VDOMs.", keyed=True
        ),
    },
    "user": {
        "fortitoken": Resource(
            "monitor",
            "user/fortitoken",
            "List FortiToken hardware/software tokens and their status.",
            keyed=False,
        ),
        "group": Resource("cmdb", "user/group", "List all user groups.", keyed=True),
        "ldap": Resource(
            "cmdb",
            "user/ldap",
            "List all LDAP authentication server configurations.",
            keyed=True,
        ),
        "local": Resource(
            "cmdb", "user/local", "List all local user accounts.", keyed=True
        ),
        "radius": Resource(
            "cmdb",
            "user/radius",
            "List all RADIUS authentication server configurations.",
            keyed=True,
        ),
        "saml": Resource(
            "cmdb",
            "user/saml",
            "List all SAML identity provider configurations.",
            keyed=True,
        ),
        "tacacs": Resource(
            "cmdb",
            "user/tacacs+",
            "List all TACACS+ authentication server configurations.",
            keyed=True,
        ),
    },
    "vpn": {
        "certificate_ca": Resource(
            "cmdb", "vpn.certificate/ca", "List all VPN CA certificates.", keyed=True
        ),
        "certificate_local": Resource(
            "cmdb",
            "vpn.certificate/local",
            "List all VPN local (device) certificates.",
            keyed=True,
        ),
        "certificate_ocsp_server": Resource(
            "cmdb",
            "vpn.certificate/ocsp-server",
            "List OCSP server configurations for certificate revocation checking.",
            keyed=True,
        ),
        "certificate_remote": Resource(
            "cmdb",
            "vpn.certificate/remote",
            "List all remote (peer) VPN certificates.",
            keyed=True,
        ),
        "certificate_valid": Resource(
            "monitor",
            "vpn-certificate/cert",
            "Check validity status of all VPN-related certificates.",
            keyed=False,
        ),
        "ipsec": Resource(
            "monitor",
            "vpn/ipsec",
            "Get status of all IPsec VPN tunnels (up/down, bytes transferred, SAs).",
            keyed=False,
        ),
        "ipsec_phase1": Resource(
            "cmdb",
            "vpn.ipsec/phase1-interface",
            "List all IPsec VPN Phase 1 (IKE gateway) interfaces.",
            keyed=True,
        ),
        "ipsec_phase2": Resource(
            "cmdb",
            "vpn.ipsec/phase2-interface",
            "List all IPsec VPN Phase 2 (SA / child SA) selectors.",
            keyed=True,
        ),
        "ssl": Resource(
            "monitor", "vpn/ssl", "List active SSL VPN sessions.", keyed=False
        ),
        "ssl_portal": Resource(
            "cmdb", "vpn.ssl.web/portal", "List all SSL VPN portals.", keyed=True
        ),
        "ssl_settings": Resource(
            "cmdb",
            "vpn.ssl/settings",
            "Get SSL VPN global settings (port, certificates, idle timeout, etc.).",
            keyed=False,
        ),
        "ssl_web_host_check_software": Resource(
            "cmdb",
            "vpn.ssl.web/host-check-software",
            "List SSL VPN host check software (endpoint compliance) rules.",
            keyed=True,
        ),
    },
    "wireless": {
        "controller_setting": Resource(
            "cmdb",
            "wireless-controller/setting",
            "Get wireless controller global settings.",
            keyed=False,
        ),
        "hotspot20_profile": Resource(
            "cmdb",
            "wireless-controller.hotspot20/hs-profile",
            "List all Hotspot 2.0 (Passpoint) profiles.",
            keyed=True,
        ),
        "interfering_ap": Resource(
            "monitor",
            "wifi/interfering_ap",
            "Get list of interfering (neighbor) Access Points detected on RF scan.",
            keyed=False,
        ),
        "managed_ap": Resource(
            "monitor",
            "wifi/managed_ap",
            "Get detailed status of all managed Access Points (online/offline, channel, clients).",
            keyed=False,
        ),
        "qos_profile": Resource(
            "cmdb",
            "wireless-controller/qos-profile",
            "List all wireless QoS profiles.",
            keyed=True,
        ),
        "rf_analysis": Resource(
            "cmdb",
            "wireless-controller/rf-analysis",
            "Get wireless RF analysis settings.",
            keyed=False,
        ),
        "rogue_ap": Resource(
            "monitor",
            "wifi/rogue_ap",
            "Get list of detected rogue (unauthorized) Access Points.",
            keyed=False,
        ),
        "spectrum_analysis": Resource(
            "monitor",
            "wifi/spectrum",
            "Get RF spectrum analysis data from APs that support it.",
            keyed=False,
        ),
        "vap": Resource(
            "cmdb",
            "wireless-controller/vap",
            "List all VAPs (Virtual APs / SSIDs).",
            keyed=True,
        ),
        "vap_group": Resource(
            "cmdb",
            "wireless-controller/vap-group",
            "List all VAP groups (SSID bundles).",
            keyed=True,
        ),
        "wtp": Resource(
            "cmdb",
            "wireless-controller/wtp",
            "List all registered WTPs (Access Points) with their configuration.",
            keyed=True,
        ),
        "wtp_profile": Resource(
            "cmdb",
            "wireless-controller/wtp-profile",
            "List all WTP (Wireless Termination Point / AP) profiles.",
            keyed=True,
        ),
    },
}


DELETE_RESOURCES: dict[str, Resource] = {
    "firewall_address": Resource(
        "cmdb",
        "firewall/address",
        "Delete an IPv4 firewall address object.",
        keyed=True,
    ),
    "firewall_addrgrp": Resource(
        "cmdb", "firewall/addrgrp", "Delete an IPv4 address group.", keyed=True
    ),
    "firewall_policy": Resource(
        "cmdb", "firewall/policy", "Delete an IPv4 firewall policy.", keyed=True
    ),
    "firewall_vip": Resource(
        "cmdb", "firewall/vip", "Delete a Virtual IP object.", keyed=True
    ),
    "ips_sensor": Resource(
        "cmdb", "ips/sensor", "Delete an IPS sensor profile.", keyed=True
    ),
    "router_static": Resource(
        "cmdb", "router/static", "Delete a static route.", keyed=True
    ),
    "system_admin": Resource(
        "cmdb", "system/admin", "Delete an administrator account.", keyed=True
    ),
    "system_interface": Resource(
        "cmdb", "system/interface", "Delete a network interface.", keyed=True
    ),
    "user_group": Resource("cmdb", "user/group", "Delete a user group.", keyed=True),
    "user_local": Resource(
        "cmdb", "user/local", "Delete a local user account.", keyed=True
    ),
    "vpn_ipsec_phase1": Resource(
        "cmdb",
        "vpn.ipsec/phase1-interface",
        "Delete an IPsec Phase 1 tunnel interface.",
        keyed=True,
    ),
    "vpn_ipsec_phase2": Resource(
        "cmdb",
        "vpn.ipsec/phase2-interface",
        "Delete an IPsec Phase 2 selector.",
        keyed=True,
    ),
    "vpn_ssl_portal": Resource(
        "cmdb", "vpn.ssl.web/portal", "Delete an SSL VPN portal.", keyed=True
    ),
    "wifi_vap": Resource(
        "cmdb",
        "wireless-controller/vap",
        "Delete a VAP (SSID) wireless network.",
        keyed=True,
    ),
    "wifi_wtp": Resource(
        "cmdb",
        "wireless-controller/wtp",
        "Deauthorize (remove) a WTP (Access Point) from the controller.",
        keyed=True,
    ),
}
