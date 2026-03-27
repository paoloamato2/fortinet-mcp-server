"""Generic pass-through tools — cover ALL 1536 FortiOS API endpoints.

These tools allow calling any FortiOS REST API endpoint without needing a
dedicated typed tool. They are the escape-hatch for endpoints that are not
yet covered by a specific tool module.
"""

from __future__ import annotations

import json
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP, Context
from pydantic import Field

from fortios_client import FortiOSClient, FortiOSError


def register(mcp: FastMCP) -> None:  # noqa: C901
    """Register all generic tools onto the FastMCP instance."""

    # ------------------------------------------------------------------
    # CMDB generic tools  (/api/v2/cmdb/…)
    # ------------------------------------------------------------------

    @mcp.tool()
    async def cmdb_list(
        ctx: Context,
        resource_path: Annotated[
            str,
            Field(
                description=(
                    "CMDB resource path without leading slash. "
                    "Examples: 'firewall/policy', 'system/interface', 'vpn.ipsec/phase1-interface', "
                    "'router/static', 'user/local'"
                )
            ),
        ],
        filters: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Optional FortiOS filter string. "
                    "Syntax: 'field==value' or 'field=@substring'. "
                    "Multiple filters separated by '&'. "
                    "Example: 'status==enable&action==accept'"
                ),
            ),
        ] = None,
        start: Annotated[
            int | None,
            Field(default=None, description="Pagination offset (0-based)."),
        ] = None,
        count: Annotated[
            int | None,
            Field(default=None, description="Maximum number of results to return."),
        ] = None,
        format_fields: Annotated[
            str | None,
            Field(
                default=None,
                description="Comma-separated list of fields to return. Reduces response size.",
            ),
        ] = None,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all objects of a CMDB resource type.

        Covers any GET on /api/v2/cmdb/{resource_path}.
        Returns the full FortiOS JSON response including results array and metadata.
        """
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        params: dict[str, Any] = {}
        if filters:
            params["filter"] = filters
        if start is not None:
            params["start"] = start
        if count is not None:
            params["count"] = count
        if format_fields:
            params["format"] = format_fields
        try:
            return await client.cmdb_get(resource_path, params or None, vdom=vdom)
        except FortiOSError as exc:
            await ctx.error(f"cmdb_list error: {exc}")
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def cmdb_get(
        ctx: Context,
        resource_path: Annotated[
            str,
            Field(
                description=(
                    "Full CMDB path including the key. "
                    "Examples: 'firewall/policy/1', 'system/interface/port1', "
                    "'vpn.ipsec/phase1-interface/my-tunnel'"
                )
            ),
        ],
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Get a single CMDB configuration object by its primary key.

        Covers any GET on /api/v2/cmdb/{resource}/{key}.
        """
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get(resource_path, vdom=vdom)
        except FortiOSError as exc:
            await ctx.error(f"cmdb_get error: {exc}")
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def cmdb_create(
        ctx: Context,
        resource_path: Annotated[
            str,
            Field(
                description=(
                    "CMDB collection path (without key). "
                    "Example: 'firewall/policy', 'system/interface', 'router/static'"
                )
            ),
        ],
        data: Annotated[
            str,
            Field(
                description=(
                    "JSON string with the object properties to create. "
                    "Must comply with the FortiOS schema for this resource. "
                    "Example: '{\"name\": \"my-addr\", \"type\": \"ipmask\", \"subnet\": \"10.0.0.0/24\"}'"
                )
            ),
        ],
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Create a new CMDB configuration object (POST).

        Covers any POST on /api/v2/cmdb/{resource_path}.
        """
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            body = json.loads(data)
        except json.JSONDecodeError as exc:
            return {"error": f"Invalid JSON in data: {exc}"}
        try:
            return await client.cmdb_post(resource_path, body, vdom=vdom)
        except FortiOSError as exc:
            await ctx.error(f"cmdb_create error: {exc}")
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def cmdb_update(
        ctx: Context,
        resource_path: Annotated[
            str,
            Field(
                description=(
                    "Full CMDB path including the key. "
                    "Example: 'firewall/policy/1', 'system/interface/port1'"
                )
            ),
        ],
        data: Annotated[
            str,
            Field(
                description=(
                    "JSON string with properties to update (full object replacement via PUT). "
                    "Must include all required fields for the object."
                )
            ),
        ],
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Update/replace a CMDB configuration object (PUT).

        Covers any PUT on /api/v2/cmdb/{resource_path}/{key}.
        """
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            body = json.loads(data)
        except json.JSONDecodeError as exc:
            return {"error": f"Invalid JSON in data: {exc}"}
        try:
            return await client.cmdb_put(resource_path, body, vdom=vdom)
        except FortiOSError as exc:
            await ctx.error(f"cmdb_update error: {exc}")
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def cmdb_delete(
        ctx: Context,
        resource_path: Annotated[
            str,
            Field(
                description=(
                    "Full CMDB path including the key to delete. "
                    "Example: 'firewall/policy/10', 'firewall/address/my-host'"
                )
            ),
        ],
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Delete a CMDB configuration object.

        Covers any DELETE on /api/v2/cmdb/{resource_path}/{key}.
        """
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_delete(resource_path, vdom=vdom)
        except FortiOSError as exc:
            await ctx.error(f"cmdb_delete error: {exc}")
            return {"error": str(exc), "status_code": exc.status_code}

    # ------------------------------------------------------------------
    # Monitor generic tools  (/api/v2/monitor/…)
    # ------------------------------------------------------------------

    @mcp.tool()
    async def monitor_get(
        ctx: Context,
        monitor_path: Annotated[
            str,
            Field(
                description=(
                    "Monitor resource path. "
                    "Examples: 'system/status', 'firewall/session', 'vpn/ipsec', "
                    "'router/ipv4', 'wifi/managed_ap', 'user/firewall'"
                )
            ),
        ],
        extra_params: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Optional JSON string with additional query parameters. "
                    "Example: '{\"tunnel_name\": \"my-vpn\"}'"
                ),
            ),
        ] = None,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Retrieve real-time operational data from any monitor endpoint.

        Covers any GET on /api/v2/monitor/{monitor_path}.
        """
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        params: dict[str, Any] | None = None
        if extra_params:
            try:
                params = json.loads(extra_params)
            except json.JSONDecodeError as exc:
                return {"error": f"Invalid JSON in extra_params: {exc}"}
        try:
            return await client.monitor_get(monitor_path, params, vdom=vdom)
        except FortiOSError as exc:
            await ctx.error(f"monitor_get error: {exc}")
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def monitor_action(
        ctx: Context,
        monitor_path: Annotated[
            str,
            Field(
                description=(
                    "Monitor action path. "
                    "Examples: 'firewall/session/close_all', "
                    "'vpn/ipsec/tunnel_down', 'system/config/backup', "
                    "'wifi/managed_ap/restart'"
                )
            ),
        ],
        body: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Optional JSON string with action parameters. "
                    "Example: '{\"mkey\": \"tunnel-name\"}'"
                ),
            ),
        ] = None,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Trigger a monitor action (POST) on any monitor endpoint.

        Covers any POST on /api/v2/monitor/{monitor_path}.
        """
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        body_dict: dict[str, Any] = {}
        if body:
            try:
                body_dict = json.loads(body)
            except json.JSONDecodeError as exc:
                return {"error": f"Invalid JSON in body: {exc}"}
        try:
            return await client.monitor_post(monitor_path, body_dict, vdom=vdom)
        except FortiOSError as exc:
            await ctx.error(f"monitor_action error: {exc}")
            return {"error": str(exc), "status_code": exc.status_code}

    # ------------------------------------------------------------------
    # Log generic tool  (/api/v2/log/…)
    # ------------------------------------------------------------------

    @mcp.tool()
    async def log_get(
        ctx: Context,
        log_path: Annotated[
            str,
            Field(
                description=(
                    "Log API path. "
                    "Examples: 'disk/traffic/forward', 'memory/event/system', "
                    "'fortianalyzer/traffic/local', 'disk/virus/archive'"
                )
            ),
        ],
        extra_params: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Optional JSON string with query params like filters, rows, start. "
                    "Example: '{\"rows\": 100, \"start\": 0, \"filter\": \"srcip==10.0.0.1\"}'"
                ),
            ),
        ] = None,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Retrieve log entries from disk, memory, FortiAnalyzer, or FortiCloud.

        Covers any GET on /api/v2/log/{log_path}.
        """
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        params: dict[str, Any] | None = None
        if extra_params:
            try:
                params = json.loads(extra_params)
            except json.JSONDecodeError as exc:
                return {"error": f"Invalid JSON in extra_params: {exc}"}
        try:
            return await client.log_get(log_path, params, vdom=vdom)
        except FortiOSError as exc:
            await ctx.error(f"log_get error: {exc}")
            return {"error": str(exc), "status_code": exc.status_code}

    # ------------------------------------------------------------------
    # Service generic tool  (/api/v2/service/…)
    # ------------------------------------------------------------------

    @mcp.tool()
    async def service_call(
        ctx: Context,
        service_path: Annotated[
            str,
            Field(
                description=(
                    "Service API path. "
                    "Examples: 'system/psirt-vulnerabilities', "
                    "'security-rating/report', "
                    "'sniffer/list', 'sniffer/start'"
                )
            ),
        ],
        method: Annotated[
            str,
            Field(
                default="GET",
                description="HTTP method: GET or POST.",
            ),
        ] = "GET",
        body: Annotated[
            str | None,
            Field(
                default=None,
                description="Optional JSON body for POST requests.",
            ),
        ] = None,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Call any FortiOS Service API endpoint.

        Covers all GET/POST on /api/v2/service/{service_path}.
        """
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        if method.upper() == "POST":
            body_dict: dict[str, Any] = {}
            if body:
                try:
                    body_dict = json.loads(body)
                except json.JSONDecodeError as exc:
                    return {"error": f"Invalid JSON in body: {exc}"}
            try:
                return await client.service_post(service_path, body_dict, vdom=vdom)
            except FortiOSError as exc:
                await ctx.error(f"service_call POST error: {exc}")
                return {"error": str(exc), "status_code": exc.status_code}
        else:
            try:
                return await client.service_get(service_path, vdom=vdom)
            except FortiOSError as exc:
                await ctx.error(f"service_call GET error: {exc}")
                return {"error": str(exc), "status_code": exc.status_code}
