"""Routing configuration and monitoring tools.

Covers /api/v2/cmdb/router/… and /api/v2/monitor/router/…
"""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP, Context
from pydantic import Field

from fortios_client import FortiOSClient, FortiOSError


def register(mcp: FastMCP) -> None:
    """Register all routing tools."""

    # ==================================================================
    # STATIC ROUTES
    # ==================================================================

    @mcp.tool()
    async def router_static_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List all IPv4 static routes."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("router/static", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def router_static_get(
        ctx: Context,
        seq_num: Annotated[int, Field(description="Static route sequence number.")],
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get a specific static route by sequence number."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get(f"router/static/{seq_num}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
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
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Create a new static route."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
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

    @mcp.tool()
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
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Update an existing static route."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
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

    @mcp.tool()
    async def router_static_delete(
        ctx: Context,
        seq_num: Annotated[int, Field(description="Route sequence number to delete.")],
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Delete a static route."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_delete(f"router/static/{seq_num}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # STATIC ROUTES (IPv6)
    # ==================================================================

    @mcp.tool()
    async def router_static6_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List all IPv6 static routes."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("router/static6", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # POLICY ROUTES
    # ==================================================================

    @mcp.tool()
    async def router_policy_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List all policy-based routing rules."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("router/policy", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # OSPF
    # ==================================================================

    @mcp.tool()
    async def router_ospf_get(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get OSPF routing configuration (areas, networks, neighbors, redistribute)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("router/ospf", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def router_ospf6_get(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get OSPFv3 (IPv6) routing configuration."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("router/ospf6", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # BGP
    # ==================================================================

    @mcp.tool()
    async def router_bgp_get(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get BGP routing configuration (ASN, peers, networks, redistribute)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("router/bgp", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
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
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Update BGP global configuration (AS number, router ID)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
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
    # RIP
    # ==================================================================

    @mcp.tool()
    async def router_rip_get(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get RIPv1/v2 routing configuration."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("router/rip", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # PREFIX LISTS & ROUTE MAPS
    # ==================================================================

    @mcp.tool()
    async def router_prefix_list_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List all IPv4 prefix lists (used in route filtering)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("router/prefix-list", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def router_route_map_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List all route-maps (used for route filtering and attribute modification)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("router/route-map", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def router_community_list_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List all BGP community lists."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("router/community-list", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # ACCESS LISTS
    # ==================================================================

    @mcp.tool()
    async def router_access_list_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List all router access lists (ACL for routing)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("router/access-list", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # SD-WAN
    # ==================================================================

    @mcp.tool()
    async def router_sdwan_get(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get the SD-WAN (virtual-WAN) configuration."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("system/virtual-wan-link", vdom=vdom)
        except FortiOSError:
            # Fallback for newer firmware
            try:
                return await client.cmdb_get("system/sdwan", vdom=vdom)
            except FortiOSError as exc2:
                return {"error": str(exc2), "status_code": exc2.status_code}

    # ==================================================================
    # MONITOR: Routing Table & Operations
    # ==================================================================

    @mcp.tool()
    async def monitor_router_ipv4(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get the active IPv4 routing table (all routes in the FIB)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.monitor_get("router/ipv4", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def monitor_router_ipv6(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get the active IPv6 routing table."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.monitor_get("router/ipv6", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
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
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Perform a route lookup — find the best route for a destination IP."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        params: dict[str, Any] = {"destination": destination}
        if interface:
            params["ipintf"] = interface
        try:
            return await client.monitor_get("router/lookup", params, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def monitor_router_lookup6(
        ctx: Context,
        destination: Annotated[
            str, Field(description="IPv6 destination address to look up.")
        ],
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Perform an IPv6 route lookup."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.monitor_get(
                "router/lookup-policy", {"destination": destination}, vdom=vdom
            )
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def monitor_router_statistics(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get routing protocol statistics (BGP, OSPF, RIP adjacencies/neighbors)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.monitor_get("router/statistics", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def monitor_sdwan_health_check(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get SD-WAN performance SLA health check results."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.monitor_get("sdwan/health-check", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def monitor_sdwan_members(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get SD-WAN member interface status and bandwidth usage."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.monitor_get("sdwan/members", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}
