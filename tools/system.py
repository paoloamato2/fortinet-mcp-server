"""System configuration and monitoring tools.

Covers /api/v2/cmdb/system/… and /api/v2/monitor/system/…
"""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP, Context
from pydantic import Field

from fortios_client import FortiOSClient, FortiOSError


def register(mcp: FastMCP) -> None:
    """Register system tools."""

    # ------------------------------------------------------------------
    # System Status & Info
    # ------------------------------------------------------------------

    @mcp.tool()
    async def system_status(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get the FortiOS system status (firmware version, hostname, serial number,
        uptime, HA state, etc.)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.monitor_get("system/status", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def system_resource_usage(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get real-time resource usage: CPU, memory, disk, sessions."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.monitor_get("system/resource/usage", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def system_performance_status(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get performance statistics (CPU usage per core, memory, network throughput)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.monitor_get("system/performance/status", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def system_ha_status(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get High Availability (HA) cluster status."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.monitor_get("system/ha-statistics", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def system_firmware_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List available firmware versions for upgrade."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.monitor_get("system/firmware", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def system_time_get(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get the current system time and timezone."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("system/time", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ------------------------------------------------------------------
    # Global Configuration
    # ------------------------------------------------------------------

    @mcp.tool()
    async def system_global_get(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get FortiOS global settings (hostname, admin timeout, language, etc.)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("system/global", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def system_global_update(
        ctx: Context,
        hostname: Annotated[
            str | None, Field(default=None, description="Device hostname.")
        ] = None,
        admin_timeout: Annotated[
            int | None,
            Field(
                default=None, description="Admin console timeout in minutes (1-480)."
            ),
        ] = None,
        timezone: Annotated[
            str | None,
            Field(default=None, description="Timezone (e.g. '28' for UTC+1 Rome)."),
        ] = None,
        language: Annotated[
            str | None,
            Field(
                default=None,
                description="GUI language: english, simch, japanese, korean, spanish, trach, french, portuguese.",
            ),
        ] = None,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Update FortiOS global settings (partial update — only specified fields change)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        body: dict[str, Any] = {}
        if hostname is not None:
            body["hostname"] = hostname
        if admin_timeout is not None:
            body["admintimeout"] = admin_timeout
        if timezone is not None:
            body["timezone"] = timezone
        if language is not None:
            body["language"] = language
        if not body:
            return {"error": "No fields to update were specified."}
        try:
            return await client.cmdb_put("system/global", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ------------------------------------------------------------------
    # Network Interfaces
    # ------------------------------------------------------------------

    @mcp.tool()
    async def system_interface_list(
        ctx: Context,
        include_vlan: Annotated[
            bool, Field(default=True, description="Include VLAN sub-interfaces.")
        ] = True,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List all network interfaces (physical, VLAN, loopback, aggregate, tunnel)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        params: dict[str, Any] = {}
        if not include_vlan:
            params["filter"] = "type!=vlan"
        try:
            return await client.cmdb_get("system/interface", params or None, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def system_interface_get(
        ctx: Context,
        name: Annotated[
            str, Field(description="Interface name (e.g. 'port1', 'wan1', 'internal').")
        ],
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get the configuration of a specific interface."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get(f"system/interface/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def system_interface_create(
        ctx: Context,
        name: Annotated[str, Field(description="Interface name.")],
        interface_type: Annotated[
            str,
            Field(
                description="Interface type: physical, vlan, loopback, tunnel, aggregate, vap-switch, etc."
            ),
        ],
        ip: Annotated[
            str | None,
            Field(
                default=None,
                description="IP address and mask (e.g. '192.168.10.1 255.255.255.0').",
            ),
        ] = None,
        vlanid: Annotated[
            int | None,
            Field(default=None, description="VLAN ID (1-4094) for VLAN interfaces."),
        ] = None,
        interface: Annotated[
            str | None,
            Field(
                default=None,
                description="Parent physical interface for VLAN sub-interfaces.",
            ),
        ] = None,
        description: Annotated[
            str | None, Field(default=None, description="Interface description.")
        ] = None,
        alias: Annotated[
            str | None, Field(default=None, description="Alias name.")
        ] = None,
        status: Annotated[
            str, Field(default="up", description="Administrative status: up or down.")
        ] = "up",
        allowaccess: Annotated[
            str | None,
            Field(
                default=None,
                description="Allowed management access (space-separated): ping https ssh snmp http telnet.",
            ),
        ] = None,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Create a new network interface."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        body: dict[str, Any] = {"name": name, "type": interface_type, "status": status}
        if ip:
            body["ip"] = ip
        if vlanid is not None:
            body["vlanid"] = vlanid
        if interface:
            body["interface"] = interface
        if description:
            body["description"] = description
        if alias:
            body["alias"] = alias
        if allowaccess:
            body["allowaccess"] = allowaccess
        try:
            return await client.cmdb_post("system/interface", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def system_interface_update(
        ctx: Context,
        name: Annotated[str, Field(description="Interface name to update.")],
        ip: Annotated[
            str | None,
            Field(default=None, description="New IP address and mask."),
        ] = None,
        status: Annotated[
            str | None,
            Field(default=None, description="Administrative status: up or down."),
        ] = None,
        description: Annotated[
            str | None, Field(default=None, description="New description.")
        ] = None,
        alias: Annotated[
            str | None, Field(default=None, description="New alias.")
        ] = None,
        allowaccess: Annotated[
            str | None, Field(default=None, description="New allowaccess string.")
        ] = None,
        mtu: Annotated[
            int | None, Field(default=None, description="MTU value (68-9000).")
        ] = None,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Update an existing network interface (only specified fields are changed)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        body: dict[str, Any] = {}
        if ip is not None:
            body["ip"] = ip
        if status is not None:
            body["status"] = status
        if description is not None:
            body["description"] = description
        if alias is not None:
            body["alias"] = alias
        if allowaccess is not None:
            body["allowaccess"] = allowaccess
        if mtu is not None:
            body["mtu"] = mtu
        if not body:
            return {"error": "No fields to update were specified."}
        try:
            return await client.cmdb_put(f"system/interface/{name}", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def system_interface_delete(
        ctx: Context,
        name: Annotated[str, Field(description="Interface name to delete.")],
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Delete a network interface."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_delete(f"system/interface/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ------------------------------------------------------------------
    # DNS
    # ------------------------------------------------------------------

    @mcp.tool()
    async def system_dns_get(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get DNS server configuration (primary, secondary, search domains)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("system/dns", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def system_dns_update(
        ctx: Context,
        primary: Annotated[
            str | None, Field(default=None, description="Primary DNS server IP.")
        ] = None,
        secondary: Annotated[
            str | None, Field(default=None, description="Secondary DNS server IP.")
        ] = None,
        domain: Annotated[
            str | None, Field(default=None, description="Local domain name.")
        ] = None,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Update DNS configuration."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        body: dict[str, Any] = {}
        if primary:
            body["primary"] = primary
        if secondary:
            body["secondary"] = secondary
        if domain:
            body["domain"] = [{"domain": domain}]
        if not body:
            return {"error": "No fields to update were specified."}
        try:
            return await client.cmdb_put("system/dns", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ------------------------------------------------------------------
    # NTP
    # ------------------------------------------------------------------

    @mcp.tool()
    async def system_ntp_get(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get NTP synchronization configuration."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("system/ntp", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def system_ntp_update(
        ctx: Context,
        ntpsync: Annotated[
            str,
            Field(
                default="enable",
                description="Enable or disable NTP: enable or disable.",
            ),
        ] = "enable",
        server: Annotated[
            str | None, Field(default=None, description="NTP server hostname or IP.")
        ] = None,
        syncinterval: Annotated[
            int | None,
            Field(
                default=None,
                description="Synchronization interval in minutes (1-1440).",
            ),
        ] = None,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Update NTP configuration."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        body: dict[str, Any] = {"ntpsync": ntpsync}
        if server:
            body["ntpserver"] = [
                {"server": server, "ntpv3": "disable", "authentication": "disable"}
            ]
        if syncinterval is not None:
            body["syncinterval"] = syncinterval
        try:
            return await client.cmdb_put("system/ntp", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ------------------------------------------------------------------
    # Admin accounts
    # ------------------------------------------------------------------

    @mcp.tool()
    async def system_admin_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List all administrator accounts."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("system/admin", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def system_admin_get(
        ctx: Context,
        name: Annotated[str, Field(description="Administrator account name.")],
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get a specific administrator account configuration."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get(f"system/admin/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def system_admin_create(
        ctx: Context,
        name: Annotated[str, Field(description="New administrator username.")],
        password: Annotated[
            str, Field(description="Password for the new admin account.")
        ],
        profile: Annotated[
            str,
            Field(
                default="super_admin",
                description="Admin profile: super_admin, prof_admin, or a custom profile name.",
            ),
        ] = "super_admin",
        comments: Annotated[
            str | None, Field(default=None, description="Optional comment.")
        ] = None,
        trusthost1: Annotated[
            str | None,
            Field(
                default=None,
                description="Trusted host 1 (CIDR notation e.g. '192.168.1.0/24').",
            ),
        ] = None,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Create a new administrator account."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        body: dict[str, Any] = {
            "name": name,
            "password": password,
            "accprofile": profile,
        }
        if comments:
            body["comments"] = comments
        if trusthost1:
            body["trusthost1"] = trusthost1
        try:
            return await client.cmdb_post("system/admin", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def system_admin_delete(
        ctx: Context,
        name: Annotated[
            str, Field(description="Administrator account name to delete.")
        ],
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Delete an administrator account."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_delete(f"system/admin/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ------------------------------------------------------------------
    # DHCP Server
    # ------------------------------------------------------------------

    @mcp.tool()
    async def system_dhcp_server_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List all DHCP server instances."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("system.dhcp/server", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def system_dhcp_server_get(
        ctx: Context,
        server_id: Annotated[int, Field(description="DHCP server ID.")],
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get a specific DHCP server configuration."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get(f"system.dhcp/server/{server_id}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def system_dhcp_server_create(
        ctx: Context,
        interface: Annotated[
            str, Field(description="Interface to bind the DHCP server to.")
        ],
        lease_time: Annotated[
            int, Field(default=86400, description="Lease time in seconds.")
        ],
        ip_range_start: Annotated[
            str, Field(description="Start IP of the address pool.")
        ],
        ip_range_end: Annotated[str, Field(description="End IP of the address pool.")],
        gateway: Annotated[
            str | None, Field(default=None, description="Default gateway IP.")
        ] = None,
        dns_server1: Annotated[
            str | None, Field(default=None, description="Primary DNS server.")
        ] = None,
        domain: Annotated[
            str | None, Field(default=None, description="DNS domain.")
        ] = None,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Create a new DHCP server."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        body: dict[str, Any] = {
            "status": "enable",
            "interface": interface,
            "lease-time": lease_time,
            "ip-range": [{"start-ip": ip_range_start, "end-ip": ip_range_end}],
        }
        if gateway:
            body["default-gateway"] = gateway
        if dns_server1:
            body["dns-server1"] = dns_server1
        if domain:
            body["domain"] = domain
        try:
            return await client.cmdb_post("system.dhcp/server", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ------------------------------------------------------------------
    # SNMP
    # ------------------------------------------------------------------

    @mcp.tool()
    async def system_snmp_sysinfo_get(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get SNMP system info (contact, location, description, trap thresholds)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("system.snmp/sysinfo", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def system_snmp_community_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List SNMP v1/v2c communities."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("system.snmp/community", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def system_snmp_user_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List SNMPv3 users."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("system.snmp/user", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ------------------------------------------------------------------
    # FortiGuard / Auto-Update
    # ------------------------------------------------------------------

    @mcp.tool()
    async def system_fortiguard_status(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get FortiGuard service registration and update status."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.monitor_get("license/status", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def system_autoupdate_schedule_get(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get the FortiGuard auto-update schedule."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("system.autoupdate/schedule", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ------------------------------------------------------------------
    # Certificates
    # ------------------------------------------------------------------

    @mcp.tool()
    async def certificate_local_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List local (device) certificates."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("certificate/local", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def certificate_ca_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List trusted CA certificates."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("certificate/ca", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ------------------------------------------------------------------
    # VDOM list
    # ------------------------------------------------------------------

    @mcp.tool()
    async def system_vdom_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List all configured VDOMs."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("system/vdom", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ------------------------------------------------------------------
    # Syslog
    # ------------------------------------------------------------------

    @mcp.tool()
    async def log_syslogd_get(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get the primary Syslog server configuration."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("log.syslogd/setting", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}
