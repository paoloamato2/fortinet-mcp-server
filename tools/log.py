"""Log retrieval and search tools.

Covers /api/v2/log/{source}/{type}/… for disk, memory, FortiAnalyzer,
FortiCloud log retrieval and the /log/search/… async search API.
"""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP, Context
from pydantic import Field

from fortios_client import FortiOSClient, FortiOSError


# Log source backends
_BACKENDS = ("disk", "memory", "fortianalyzer", "forticloud")

# Log types (traffic subtypes map to traffic/{subtype})
_LOG_TYPES = (
    "traffic",
    "event",
    "utm",
    "virus",
    "webfilter",
    "attack",
    "spam",
    "anomaly",
    "voip",
    "dlp",
    "app-ctrl",
    "emailfilter",
    "fortimail",
    "netscan",
    "gtp",
    "dns",
    "ssh",
    "ssl",
    "file-filter",
    "cifs",
    "icap",
)


def register(mcp: FastMCP) -> None:
    """Register all log tools."""

    # ==================================================================
    # GENERIC LOG QUERY (any backend + type)
    # ==================================================================

    @mcp.tool()
    async def log_query(
        ctx: Context,
        source: Annotated[
            str,
            Field(
                default="disk",
                description=(
                    "Log storage backend: disk, memory, fortianalyzer, forticloud. "
                    "Use 'disk' (default) for local logs."
                ),
            ),
        ] = "disk",
        log_type: Annotated[
            str,
            Field(
                default="traffic",
                description=(
                    "Log type: traffic, event, utm, virus, webfilter, attack, spam, anomaly, "
                    "voip, dlp, app-ctrl, emailfilter, dns, ssh, ssl, file-filter. "
                    "For traffic subtypes use: traffic/forward, traffic/local, traffic/sniffer."
                ),
            ),
        ] = "traffic",
        filter_expr: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Filter expression. FortiOS filter syntax. "
                    "Examples: 'srcip==10.0.0.1', 'action==blocked', 'user==john'. "
                    "Combine with 'and': 'srcip==10.0.0.1 and dstport==443'."
                ),
            ),
        ] = None,
        rows: Annotated[
            int, Field(default=100, description="Maximum number of log entries to return (1-10000).")
        ] = 100,
        start: Annotated[
            int, Field(default=0, description="Offset for pagination.")
        ] = 0,
        extra_params: Annotated[
            dict[str, Any] | None,
            Field(default=None, description="Additional query parameters as a dict."),
        ] = None,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Query logs from FortiOS with flexible filtering.

        Returns log entries from the specified backend and type.
        Results include timestamps, sources, destinations, actions, and UTM verdicts.
        """
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        if source not in _BACKENDS:
            return {"error": f"Invalid source '{source}'. Must be one of: {', '.join(_BACKENDS)}"}
        path = f"{source}/{log_type}"
        params: dict[str, Any] = {"rows": rows, "start": start}
        if filter_expr:
            params["filter"] = filter_expr
        if extra_params:
            params.update(extra_params)
        try:
            return await client.log_get(path, params, vdom=vdom)
        except FortiOSError as exc:
            await ctx.error(f"log_query error: {exc}")
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # TRAFFIC LOGS
    # ==================================================================

    @mcp.tool()
    async def log_traffic_forward(
        ctx: Context,
        rows: Annotated[int, Field(default=100, description="Max rows per page.")] = 100,
        start: Annotated[int, Field(default=0, description="Starting offset.")] = 0,
        srcip: Annotated[str | None, Field(default=None, description="Filter by source IP.")] = None,
        dstip: Annotated[str | None, Field(default=None, description="Filter by destination IP.")] = None,
        dstport: Annotated[int | None, Field(default=None, description="Filter by destination port.")] = None,
        action: Annotated[str | None, Field(default=None, description="Filter by action: accept, deny, close, etc.")] = None,
        policy_id: Annotated[int | None, Field(default=None, description="Filter by firewall policy ID.")] = None,
        source: Annotated[str, Field(default="disk", description="Log source: disk or memory.")] = "disk",
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Query forward traffic logs with optional per-field filters."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        filters = []
        if srcip:
            filters.append(f"srcip=={srcip}")
        if dstip:
            filters.append(f"dstip=={dstip}")
        if dstport is not None:
            filters.append(f"dstport=={dstport}")
        if action:
            filters.append(f"action=={action}")
        if policy_id is not None:
            filters.append(f"policyid=={policy_id}")
        params: dict[str, Any] = {"rows": rows, "start": start}
        if filters:
            params["filter"] = " and ".join(filters)
        try:
            return await client.log_get(f"{source}/traffic/forward", params, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def log_traffic_local(
        ctx: Context,
        rows: Annotated[int, Field(default=100, description="Max rows per page.")] = 100,
        start: Annotated[int, Field(default=0, description="Starting offset.")] = 0,
        source: Annotated[str, Field(default="disk", description="Log source: disk or memory.")] = "disk",
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Query local traffic logs (traffic to/from the FortiGate itself)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.log_get(f"{source}/traffic/local", {"rows": rows, "start": start}, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # EVENT LOGS
    # ==================================================================

    @mcp.tool()
    async def log_event_system(
        ctx: Context,
        rows: Annotated[int, Field(default=100, description="Max rows per page.")] = 100,
        start: Annotated[int, Field(default=0, description="Starting offset.")] = 0,
        source: Annotated[str, Field(default="disk", description="Log source: disk or memory.")] = "disk",
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Query system event logs (admin logins, config changes, system alerts)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.log_get(f"{source}/event/system", {"rows": rows, "start": start}, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def log_event_vpn(
        ctx: Context,
        rows: Annotated[int, Field(default=100, description="Max rows per page.")] = 100,
        start: Annotated[int, Field(default=0, description="Starting offset.")] = 0,
        source: Annotated[str, Field(default="disk", description="Log source: disk or memory.")] = "disk",
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Query VPN event logs (IPsec SA negotiations, SSL VPN logins/logouts)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.log_get(f"{source}/event/vpn", {"rows": rows, "start": start}, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def log_event_user(
        ctx: Context,
        rows: Annotated[int, Field(default=100, description="Max rows per page.")] = 100,
        start: Annotated[int, Field(default=0, description="Starting offset.")] = 0,
        username: Annotated[str | None, Field(default=None, description="Filter by username.")] = None,
        source: Annotated[str, Field(default="disk", description="Log source: disk or memory.")] = "disk",
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Query user authentication event logs."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        params: dict[str, Any] = {"rows": rows, "start": start}
        if username:
            params["filter"] = f"user=={username}"
        try:
            return await client.log_get(f"{source}/event/user", params, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # SECURITY (UTM / THREAT) LOGS
    # ==================================================================

    @mcp.tool()
    async def log_virus(
        ctx: Context,
        rows: Annotated[int, Field(default=100, description="Max rows per page.")] = 100,
        start: Annotated[int, Field(default=0, description="Starting offset.")] = 0,
        source: Annotated[str, Field(default="disk", description="Log source: disk or memory.")] = "disk",
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Query antivirus threat logs."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.log_get(f"{source}/virus/archive", {"rows": rows, "start": start}, vdom=vdom)
        except FortiOSError as exc:
            try:
                return await client.log_get(f"{source}/virus", {"rows": rows, "start": start}, vdom=vdom)
            except FortiOSError as exc2:
                return {"error": str(exc2), "status_code": exc2.status_code}

    @mcp.tool()
    async def log_webfilter(
        ctx: Context,
        rows: Annotated[int, Field(default=100, description="Max rows per page.")] = 100,
        start: Annotated[int, Field(default=0, description="Starting offset.")] = 0,
        action: Annotated[
            str | None,
            Field(default=None, description="Filter by action: blocked, allowed, warning, etc."),
        ] = None,
        source: Annotated[str, Field(default="disk", description="Log source: disk or memory.")] = "disk",
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Query web filter (URL category/block) logs."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        params: dict[str, Any] = {"rows": rows, "start": start}
        if action:
            params["filter"] = f"action=={action}"
        try:
            return await client.log_get(f"{source}/webfilter", params, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def log_ips_attack(
        ctx: Context,
        rows: Annotated[int, Field(default=100, description="Max rows per page.")] = 100,
        start: Annotated[int, Field(default=0, description="Starting offset.")] = 0,
        srcip: Annotated[str | None, Field(default=None, description="Filter by attacker source IP.")] = None,
        source: Annotated[str, Field(default="disk", description="Log source: disk or memory.")] = "disk",
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Query IPS intrusion detection/prevention attack logs."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        params: dict[str, Any] = {"rows": rows, "start": start}
        if srcip:
            params["filter"] = f"srcip=={srcip}"
        try:
            return await client.log_get(f"{source}/attack", params, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def log_app_ctrl(
        ctx: Context,
        rows: Annotated[int, Field(default=100, description="Max rows per page.")] = 100,
        start: Annotated[int, Field(default=0, description="Starting offset.")] = 0,
        action: Annotated[str | None, Field(default=None, description="Filter by action: pass, block.")] = None,
        source: Annotated[str, Field(default="disk", description="Log source: disk or memory.")] = "disk",
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Query Application Control logs."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        params: dict[str, Any] = {"rows": rows, "start": start}
        if action:
            params["filter"] = f"action=={action}"
        try:
            return await client.log_get(f"{source}/app-ctrl", params, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def log_dns(
        ctx: Context,
        rows: Annotated[int, Field(default=100, description="Max rows per page.")] = 100,
        start: Annotated[int, Field(default=0, description="Starting offset.")] = 0,
        source: Annotated[str, Field(default="disk", description="Log source: disk or memory.")] = "disk",
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Query DNS filter logs."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.log_get(f"{source}/dns", {"rows": rows, "start": start}, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # LOG CONFIGURATION
    # ==================================================================

    @mcp.tool()
    async def log_disk_filter_get(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Get the disk log filter settings (which log types are enabled)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("log.disk/filter", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def log_disk_setting_get(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Get the disk logging settings (log level, max log size, etc.)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("log.disk/setting", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def log_memory_setting_get(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Get the memory logging settings."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("log.memory/setting", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def log_fortianalyzer_setting_get(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Get FortiAnalyzer logging configuration (server, port, status)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("log.fortianalyzer/setting", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def log_fortianalyzer_setting_update(
        ctx: Context,
        status: Annotated[
            str | None, Field(default=None, description="Enable or disable: enable or disable.")
        ] = None,
        server: Annotated[str | None, Field(default=None, description="FortiAnalyzer IP/FQDN.")] = None,
        enc_algorithm: Annotated[
            str | None,
            Field(default=None, description="Encryption algorithm: default, high, low, disable."),
        ] = None,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Update FortiAnalyzer logging settings."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        body: dict[str, Any] = {}
        if status is not None:
            body["status"] = status
        if server is not None:
            body["server"] = server
        if enc_algorithm is not None:
            body["enc-algorithm"] = enc_algorithm
        if not body:
            return {"error": "No fields to update were specified."}
        try:
            return await client.cmdb_put("log.fortianalyzer/setting", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}
