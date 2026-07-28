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
from resources import MonitorResource
from tool_annotations import READ_ONLY
from tool_params import InstanceParam, VdomParam
from tools._read import read_resource, resource_table_doc


def register(mcp: FastMCP) -> None:
    """Register all monitoring tools."""

    async def monitor_read(
        ctx: Context,
        resource: Annotated[
            MonitorResource, Field(description="Which monitor resource to read.")
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
        return await read_resource(ctx, "monitor", resource, name, instance, vdom)

    monitor_read.__doc__ = (
        "Read live device, network and security telemetry.\n\n"
        "Omit `name` to list a resource, or pass it to fetch one object by "
        "key.\n\n" + resource_table_doc("monitor")
    )
    mcp.tool(annotations=READ_ONLY)(monitor_read)

    # ==================================================================
    # NETWORK
    # ==================================================================

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_interface_dhcp_status(
        ctx: Context,
        interface: Annotated[
            str | None,
            Field(default=None, description="Interface name to get DHCP status for."),
        ] = None,
        instance: InstanceParam = None,
        vdom: VdomParam = None,
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
    #
    # All three hit fortiview/realtime-statistics and differ only by
    # report_by. The old path (fortiview/statistics) and the old parameter
    # name ("type") both predate FortiOS 7.x: live testing on 7.6.6 on
    # 2026-07-28 showed the path 404s outright, so every one of these tools
    # was returning an error rather than data. Note that report_by silently
    # falls back to the default source view for a value FortiOS does not
    # recognise -- it does not reject one -- so a wrong value here returns
    # plausible but incorrect data. Only add a value confirmed on a device.
    # ==================================================================

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_fortiview_top_sources(
        ctx: Context,
        count: Annotated[
            int, Field(default=20, description="Number of top entries to return.")
        ] = 20,
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Get FortiView top sources (most active source IPs by session count)."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.monitor_get(
                "fortiview/realtime-statistics",
                {"report_by": "source", "count": count},
                vdom=vdom,
            )
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_fortiview_top_destinations(
        ctx: Context,
        count: Annotated[
            int, Field(default=20, description="Number of top entries to return.")
        ] = 20,
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Get FortiView top destinations (most accessed destination IPs)."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.monitor_get(
                "fortiview/realtime-statistics",
                {"report_by": "destination", "count": count},
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
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Get FortiView top applications by bandwidth or session count."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.monitor_get(
                "fortiview/realtime-statistics",
                {"report_by": "application", "count": count},
                vdom=vdom,
            )
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # ENDPOINT CONTROL
    # ==================================================================

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_endpoint_record_list(
        ctx: Context,
        count: Annotated[
            int, Field(default=100, description="Number of records to return.")
        ] = 100,
        instance: InstanceParam = None,
        vdom: VdomParam = None,
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
    # SWITCH CONTROLLER
    # ==================================================================

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_switch_controller_port_stats(
        ctx: Context,
        switch_id: Annotated[
            str | None,
            Field(default=None, description="FortiSwitch serial number to query."),
        ] = None,
        instance: InstanceParam = None,
        vdom: VdomParam = None,
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
    # CONFIG BACKUP
    # ==================================================================

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_system_config_backup(
        ctx: Context,
        scope: Annotated[
            str,
            Field(default="global", description="Backup scope: global or vdom."),
        ] = "global",
        instance: InstanceParam = None,
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
        instance: InstanceParam = None,
        vdom: VdomParam = None,
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
        instance: InstanceParam = None,
        vdom: VdomParam = None,
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
        instance: InstanceParam = None,
        vdom: VdomParam = None,
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
