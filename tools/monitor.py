"""System and network monitoring tools.

Covers /api/v2/monitor/… endpoints focused on real-time operational data
not already covered in firewall.py, vpn.py, router.py, or user.py.
"""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP, Context
from pydantic import Field

from fortios_client import FortiOSError
from instances import FortiOSAPI
from tool_annotations import READ_ONLY


def register(mcp: FastMCP) -> None:
    """Register all monitoring tools."""

    # ==================================================================
    # NETWORK
    # ==================================================================

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_network_arp_list(
        ctx: Context,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Get the ARP table (IP-to-MAC address mappings)."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.monitor_get("network/arp", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_network_lldp_neighbors(
        ctx: Context,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Get LLDP neighbor information discovered on all interfaces."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.monitor_get("network/lldp/neighbors", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_interface_dhcp_status(
        ctx: Context,
        interface: Annotated[
            str | None,
            Field(default=None, description="Interface name to get DHCP status for."),
        ] = None,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Get DHCP lease status on an interface (client side)."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        params: dict[str, Any] = {}
        if interface:
            params["interface_name"] = interface
        try:
            return await client.monitor_get("system/dhcp", params or None, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # FORTIVIEW / TOP TALKERS
    # ==================================================================

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_fortiview_top_sources(
        ctx: Context,
        count: Annotated[
            int, Field(default=20, description="Number of top entries to return.")
        ] = 20,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Get FortiView top sources (most active source IPs by session count)."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.monitor_get(
                "fortiview/statistics", {"type": "source", "count": count}, vdom=vdom
            )
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_fortiview_top_destinations(
        ctx: Context,
        count: Annotated[
            int, Field(default=20, description="Number of top entries to return.")
        ] = 20,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Get FortiView top destinations (most accessed destination IPs)."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.monitor_get(
                "fortiview/statistics",
                {"type": "destination", "count": count},
                vdom=vdom,
            )
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_fortiview_top_applications(
        ctx: Context,
        count: Annotated[
            int, Field(default=20, description="Number of top entries to return.")
        ] = 20,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Get FortiView top applications by bandwidth or session count."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.monitor_get(
                "fortiview/statistics",
                {"type": "application", "count": count},
                vdom=vdom,
            )
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_fortiview_top_threat_map(
        ctx: Context,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Get FortiView threat map data (geo-blocking source countries)."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.monitor_get(
                "fortiview/statistics", {"type": "threat"}, vdom=vdom
            )
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # LICENSE / FORTIGUARD STATUS
    # ==================================================================

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_license_status(
        ctx: Context,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Get FortiGuard license and subscription status for all services."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.monitor_get("license/status", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_license_forticare_resellers(
        ctx: Context,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Get FortiCare reseller and support contract information."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.monitor_get("license/forticare-resellers", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # ENDPOINT CONTROL
    # ==================================================================

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_endpoint_summary(
        ctx: Context,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Get endpoint control (FortiClient) summary statistics."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.monitor_get("endpoint-control/summary", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_endpoint_record_list(
        ctx: Context,
        count: Annotated[
            int, Field(default=100, description="Number of records to return.")
        ] = 100,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """List registered endpoint (FortiClient) records."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.monitor_get(
                "endpoint-control/record-list", {"count": count}, vdom=vdom
            )
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # IPS / UTM
    # ==================================================================

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_ips_anomaly(
        ctx: Context,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Get IPS anomaly detection statistics."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.monitor_get("ips/anomaly", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_utm_app_categories(
        ctx: Context,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Get UTM application category statistics."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.monitor_get("utm/app-lookup", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # SWITCH CONTROLLER
    # ==================================================================

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_switch_controller_managed_switch(
        ctx: Context,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Get status of all FortiSwitch managed switches."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.monitor_get(
                "switch-controller/managed-switch", vdom=vdom
            )
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_switch_controller_port_stats(
        ctx: Context,
        switch_id: Annotated[
            str | None,
            Field(default=None, description="FortiSwitch serial number to query."),
        ] = None,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Get per-port traffic statistics for managed FortiSwitch devices."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        params: dict[str, Any] = {}
        if switch_id:
            params["mkey"] = switch_id
        try:
            return await client.monitor_get(
                "switch-controller/port-stats", params or None, vdom=vdom
            )
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # SECURITY RATING
    # ==================================================================

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_security_rating_summary(
        ctx: Context,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Get the Security Rating summary score and findings."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.monitor_get("system/security-rating", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # CONFIG BACKUP
    # ==================================================================

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_system_config_backup(
        ctx: Context,
        scope: Annotated[
            str,
            Field(default="global", description="Backup scope: global or vdom."),
        ] = "global",
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
            ),
        ] = None,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="VDOM name (required when scope=vdom). Also routes this API request to the specified VDOM.",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Trigger a configuration backup and get the backup data (base64-encoded)."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        params: dict[str, Any] = {"scope": scope}
        if vdom:
            params["vdom"] = vdom
        try:
            return await client.monitor_get("system/config/backup", params, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # RUNNING PROCESSES
    # ==================================================================

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_system_process_list(
        ctx: Context,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """List running FortiOS processes with CPU and memory usage."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.monitor_get("system/running-processes", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # INTERFACES (real-time stats)
    # ==================================================================

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_interface_stats(
        ctx: Context,
        interface: Annotated[
            str | None,
            Field(
                default=None,
                description="Interface name. If not specified, returns all interfaces.",
            ),
        ] = None,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Get real-time interface traffic statistics (bytes in/out, errors, drops)."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        params: dict[str, Any] = {}
        if interface:
            params["interface_name"] = interface
        try:
            return await client.monitor_get(
                "system/interface/select", params or None, vdom=vdom
            )
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # DIAGNOSE / PING / TRACEROUTE
    # ==================================================================

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_network_ping(
        ctx: Context,
        destination: Annotated[
            str, Field(description="IP address or hostname to ping.")
        ],
        source_ip: Annotated[
            str | None,
            Field(
                default=None,
                description="Source IP address (selects egress interface).",
            ),
        ] = None,
        count: Annotated[
            int, Field(default=5, description="Number of ICMP pings to send.")
        ] = 5,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Ping a remote host from the FortiGate device."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        params: dict[str, Any] = {"destination": destination, "count": count}
        if source_ip:
            params["source"] = source_ip
        try:
            return await client.monitor_post(
                "network/diag-icmp-ping", params, vdom=vdom
            )
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # GEOIP
    # ==================================================================

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_geoip_lookup(
        ctx: Context,
        ip_address: Annotated[
            str, Field(description="IPv4 address to look up geolocation for.")
        ],
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Look up the geographic location (country, coordinates) of an IP address."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.monitor_get(
                "geoip/geoip-query", {"ip_addr": ip_address}, vdom=vdom
            )
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}
