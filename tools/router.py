"""Routing configuration and monitoring tools.

Covers /api/v2/cmdb/router/… and /api/v2/monitor/router/…
"""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP, Context
from pydantic import Field

from fortios_client import FortiOSError
from instances import FortiOSAPI
from resources import RouterResource
from tool_annotations import CREATES, DESTRUCTIVE, READ_ONLY
from tool_params import CountParam, InstanceParam, StartParam, VdomParam
from tools._read import read_resource, resource_table_doc


def register(mcp: FastMCP) -> None:
    """Register all routing tools."""

    async def router_read(
        ctx: Context,
        resource: Annotated[
            RouterResource, Field(description="Which router resource to read.")
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
        start: StartParam = None,
        count: CountParam = None,
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Placeholder replaced below with the generated resource table."""
        return await read_resource(
            ctx, "router", resource, name, instance, vdom, start, count
        )

    router_read.__doc__ = (
        "Read routing configuration and the live routing table.\n\n"
        "Omit `name` to list a resource, or pass it to fetch one object by "
        "key.\n\n" + resource_table_doc("router")
    )
    mcp.tool(annotations=READ_ONLY)(router_read)

    # ==================================================================
    # STATIC ROUTES
    # ==================================================================

    @mcp.tool(annotations=CREATES)
    async def router_static_create(
        ctx: Context,
        dst: Annotated[
            str,
            Field(
                description="Destination network in CIDR or 'ip mask' format (e.g. '10.10.0.0/16' or '10.10.0.0 255.255.0.0')."
            ),
        ],
        gateway: Annotated[str, Field(description="Next-hop gateway IP address.")],
        device: Annotated[
            str, Field(description="Egress interface name (e.g. 'wan1').")
        ],
        distance: Annotated[
            int, Field(default=10, description="Administrative distance (1-255).")
        ] = 10,
        priority: Annotated[
            int, Field(default=0, description="Priority (lower = preferred).")
        ] = 0,
        comment: Annotated[
            str | None, Field(default=None, description="Comment.")
        ] = None,
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Create a new static route."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        # Normalize CIDR to FortiOS "ip mask" format
        if "/" in dst:
            ip, prefix = dst.split("/")
            import ipaddress

            net = ipaddress.IPv4Network(dst, strict=False)
            dst_normalized = f"{ip} {net.netmask}"
        else:
            dst_normalized = dst
        body: dict[str, Any] = {
            "dst": dst_normalized,
            "gateway": gateway,
            "device": device,
            "distance": distance,
            "priority": priority,
        }
        if comment:
            body["comment"] = comment
        try:
            return await client.cmdb_post("router/static", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=DESTRUCTIVE)
    async def router_static_update(
        ctx: Context,
        seq_num: Annotated[int, Field(description="Route sequence number to update.")],
        gateway: Annotated[
            str | None, Field(default=None, description="New next-hop gateway.")
        ] = None,
        device: Annotated[
            str | None, Field(default=None, description="New egress interface.")
        ] = None,
        distance: Annotated[
            int | None, Field(default=None, description="New administrative distance.")
        ] = None,
        priority: Annotated[
            int | None, Field(default=None, description="New priority.")
        ] = None,
        status: Annotated[
            str | None, Field(default=None, description="Status: enable or disable.")
        ] = None,
        comment: Annotated[
            str | None, Field(default=None, description="New comment.")
        ] = None,
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Update an existing static route."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        body: dict[str, Any] = {}
        if gateway is not None:
            body["gateway"] = gateway
        if device is not None:
            body["device"] = device
        if distance is not None:
            body["distance"] = distance
        if priority is not None:
            body["priority"] = priority
        if status is not None:
            body["status"] = status
        if comment is not None:
            body["comment"] = comment
        if not body:
            return {"error": "No fields to update were specified."}
        try:
            return await client.cmdb_put(f"router/static/{seq_num}", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # BGP
    # ==================================================================

    @mcp.tool(annotations=DESTRUCTIVE)
    async def router_bgp_update(
        ctx: Context,
        as_number: Annotated[
            int | None,
            Field(default=None, description="Local BGP AS number (1-4294967295)."),
        ] = None,
        router_id: Annotated[
            str | None,
            Field(default=None, description="BGP router ID (IP address format)."),
        ] = None,
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Update BGP global configuration (AS number, router ID)."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        body: dict[str, Any] = {}
        if as_number is not None:
            body["as"] = as_number
        if router_id is not None:
            body["router-id"] = router_id
        if not body:
            return {"error": "No fields to update were specified."}
        try:
            return await client.cmdb_put("router/bgp", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # MONITOR: Routing Table & Operations
    # ==================================================================

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_router_lookup(
        ctx: Context,
        destination: Annotated[
            str,
            Field(
                description="Destination IP address to look up in the routing table."
            ),
        ],
        interface: Annotated[
            str | None,
            Field(
                default=None, description="Optional source interface for PBR lookup."
            ),
        ] = None,
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Perform a route lookup — find the best route for a destination IP."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        params: dict[str, Any] = {"destination": destination}
        if interface:
            params["ipintf"] = interface
        try:
            return await client.monitor_get("router/lookup", params, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_router_lookup6(
        ctx: Context,
        destination: Annotated[
            str, Field(description="IPv6 destination address to look up.")
        ],
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Perform an IPv6 route lookup."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.monitor_get(
                "router/lookup-policy", {"destination": destination}, vdom=vdom
            )
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}
