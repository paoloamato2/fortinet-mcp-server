"""System configuration and monitoring tools.

Covers /api/v2/cmdb/system/… and /api/v2/monitor/system/…
"""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP, Context
from pydantic import Field

from fortios_client import FortiOSError
from instances import FortiOSAPI
from resources import SystemResource
from tool_annotations import CREATES, DESTRUCTIVE, READ_ONLY
from tool_params import InstanceParam, VdomParam
from tools._read import read_resource, resource_table_doc


def register(mcp: FastMCP) -> None:
    """Register system tools."""

    async def system_read(
        ctx: Context,
        resource: Annotated[
            SystemResource, Field(description="Which system resource to read.")
        ],
        name: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Object key to fetch. Omit to list every object. "
                    "Rejected for singletons and monitor endpoints."
                ),
            ),
        ] = None,
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Placeholder replaced below with the generated resource table."""
        return await read_resource(ctx, "system", resource, name, instance, vdom)

    system_read.__doc__ = (
        "Read system configuration and device health.\n\n"
        "Omit `name` to list a resource, or pass it to fetch one object by "
        "key.\n\n" + resource_table_doc("system")
    )
    mcp.tool(annotations=READ_ONLY)(system_read)

    # ------------------------------------------------------------------
    # Global Configuration
    # ------------------------------------------------------------------

    @mcp.tool(annotations=DESTRUCTIVE)
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
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Update FortiOS global settings (partial update — only specified fields change)."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
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

    @mcp.tool(annotations=READ_ONLY)
    async def system_interface_list(
        ctx: Context,
        include_vlan: Annotated[
            bool, Field(default=True, description="Include VLAN sub-interfaces.")
        ] = True,
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """List all network interfaces (physical, VLAN, loopback, aggregate, tunnel)."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        params: dict[str, Any] = {}
        if not include_vlan:
            params["filter"] = "type!=vlan"
        try:
            return await client.cmdb_get("system/interface", params or None, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=READ_ONLY)
    async def system_interface_get(
        ctx: Context,
        name: Annotated[
            str, Field(description="Interface name (e.g. 'port1', 'wan1', 'internal').")
        ],
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Get the configuration of a specific interface."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.cmdb_get(f"system/interface/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=CREATES)
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
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Create a new network interface."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
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

    @mcp.tool(annotations=DESTRUCTIVE)
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
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Update an existing network interface (only specified fields are changed)."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
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

    @mcp.tool(annotations=DESTRUCTIVE)
    async def system_interface_delete(
        ctx: Context,
        name: Annotated[str, Field(description="Interface name to delete.")],
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Delete a network interface."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.cmdb_delete(f"system/interface/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ------------------------------------------------------------------
    # DNS
    # ------------------------------------------------------------------

    @mcp.tool(annotations=DESTRUCTIVE)
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
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Update DNS configuration."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
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

    @mcp.tool(annotations=DESTRUCTIVE)
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
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Update NTP configuration."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
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

    @mcp.tool(annotations=CREATES)
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
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Create a new administrator account."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
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

    @mcp.tool(annotations=DESTRUCTIVE)
    async def system_admin_delete(
        ctx: Context,
        name: Annotated[
            str, Field(description="Administrator account name to delete.")
        ],
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Delete an administrator account."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.cmdb_delete(f"system/admin/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ------------------------------------------------------------------
    # DHCP Server
    # ------------------------------------------------------------------

    @mcp.tool(annotations=CREATES)
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
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Create a new DHCP server."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
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
