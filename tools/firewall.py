"""Firewall configuration and monitoring tools.

Covers /api/v2/cmdb/firewall/… and /api/v2/monitor/firewall/…
"""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP, Context
from pydantic import Field

from fortios_client import FortiOSClient, FortiOSError


def register(mcp: FastMCP) -> None:
    """Register all firewall tools."""

    # ==================================================================
    # FIREWALL POLICIES  (IPv4)
    # ==================================================================

    @mcp.tool()
    async def firewall_policy_list(
        ctx: Context,
        start: Annotated[
            int, Field(default=0, description="Offset for pagination.")
        ] = 0,
        count: Annotated[
            int, Field(default=200, description="Max number of policies to return.")
        ] = 200,
        filter_srcintf: Annotated[
            str | None,
            Field(default=None, description="Filter by source interface name."),
        ] = None,
        filter_dstintf: Annotated[
            str | None,
            Field(default=None, description="Filter by destination interface name."),
        ] = None,
        filter_action: Annotated[
            str | None,
            Field(default=None, description="Filter by action: accept or deny."),
        ] = None,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List IPv4 firewall policies with optional filters.

        Returns policy ID, name, source/destination interfaces and zones,
        source/destination addresses, services, action, and status.
        """
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        params: dict[str, Any] = {"start": start, "count": count}
        filters = []
        if filter_srcintf:
            filters.append(f"srcintf=={filter_srcintf}")
        if filter_dstintf:
            filters.append(f"dstintf=={filter_dstintf}")
        if filter_action:
            filters.append(f"action=={filter_action}")
        if filters:
            params["filter"] = "&".join(filters)
        try:
            return await client.cmdb_get("firewall/policy", params, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def firewall_policy_get(
        ctx: Context,
        policy_id: Annotated[int, Field(description="Firewall policy ID number.")],
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get a specific IPv4 firewall policy by its ID."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get(f"firewall/policy/{policy_id}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def firewall_policy_create(
        ctx: Context,
        name: Annotated[str, Field(description="Policy name.")],
        srcintf: Annotated[
            str, Field(description="Source interface name (e.g. 'port1', 'any').")
        ],
        dstintf: Annotated[
            str, Field(description="Destination interface name (e.g. 'wan1', 'any').")
        ],
        srcaddr: Annotated[
            str, Field(description="Source address name (e.g. 'all', 'LAN_SUBNET').")
        ],
        dstaddr: Annotated[
            str, Field(description="Destination address name (e.g. 'all').")
        ],
        service: Annotated[
            str, Field(description="Service name (e.g. 'ALL', 'HTTP', 'HTTPS').")
        ],
        action: Annotated[
            str, Field(default="accept", description="Policy action: accept or deny.")
        ] = "accept",
        status: Annotated[
            str,
            Field(default="enable", description="Policy status: enable or disable."),
        ] = "enable",
        nat: Annotated[
            str, Field(default="disable", description="NAT: enable or disable.")
        ] = "disable",
        logtraffic: Annotated[
            str, Field(default="utm", description="Log traffic: all, utm, or disable.")
        ] = "utm",
        comments: Annotated[
            str | None, Field(default=None, description="Policy comment.")
        ] = None,
        schedule: Annotated[
            str, Field(default="always", description="Schedule name.")
        ] = "always",
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Create a new IPv4 firewall policy."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        body: dict[str, Any] = {
            "name": name,
            "srcintf": [{"name": srcintf}],
            "dstintf": [{"name": dstintf}],
            "srcaddr": [{"name": srcaddr}],
            "dstaddr": [{"name": dstaddr}],
            "service": [{"name": service}],
            "action": action,
            "status": status,
            "nat": nat,
            "logtraffic": logtraffic,
            "schedule": schedule,
        }
        if comments:
            body["comments"] = comments
        try:
            return await client.cmdb_post("firewall/policy", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def firewall_policy_update(
        ctx: Context,
        policy_id: Annotated[int, Field(description="Firewall policy ID to update.")],
        name: Annotated[
            str | None, Field(default=None, description="New policy name.")
        ] = None,
        action: Annotated[
            str | None, Field(default=None, description="New action: accept or deny.")
        ] = None,
        status: Annotated[
            str | None, Field(default=None, description="Status: enable or disable.")
        ] = None,
        nat: Annotated[
            str | None, Field(default=None, description="NAT: enable or disable.")
        ] = None,
        logtraffic: Annotated[
            str | None,
            Field(default=None, description="Log traffic: all, utm, or disable."),
        ] = None,
        comments: Annotated[
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
        """Update fields of an existing IPv4 firewall policy."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        body: dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if action is not None:
            body["action"] = action
        if status is not None:
            body["status"] = status
        if nat is not None:
            body["nat"] = nat
        if logtraffic is not None:
            body["logtraffic"] = logtraffic
        if comments is not None:
            body["comments"] = comments
        if not body:
            return {"error": "No fields to update were specified."}
        try:
            return await client.cmdb_put(
                f"firewall/policy/{policy_id}", body, vdom=vdom
            )
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def firewall_policy_delete(
        ctx: Context,
        policy_id: Annotated[int, Field(description="Firewall policy ID to delete.")],
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Delete an IPv4 firewall policy."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_delete(f"firewall/policy/{policy_id}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def firewall_policy_move(
        ctx: Context,
        policy_id: Annotated[int, Field(description="Policy ID to move.")],
        move_action: Annotated[
            str,
            Field(
                description="Move action: 'before' or 'after' relative to the neighbor policy."
            ),
        ],
        neighbor_id: Annotated[
            int,
            Field(description="ID of the neighbor policy for relative positioning."),
        ],
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Move a firewall policy (change its order in the policy table)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_put(
                f"firewall/policy/{policy_id}",
                {},
                params={"action": "move", move_action: str(neighbor_id)},
                vdom=vdom,
            )
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # FIREWALL POLICIES  (IPv6)
    # ==================================================================

    @mcp.tool()
    async def firewall_policy6_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List all IPv6 firewall policies."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("firewall/policy6", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # ADDRESS OBJECTS
    # ==================================================================

    @mcp.tool()
    async def firewall_address_list(
        ctx: Context,
        filter_type: Annotated[
            str | None,
            Field(
                default=None,
                description="Filter by address type: ipmask, iprange, fqdn, geography, wildcard, etc.",
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
        """List all IPv4 firewall address objects."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        params: dict[str, Any] = {}
        if filter_type:
            params["filter"] = f"type=={filter_type}"
        try:
            return await client.cmdb_get("firewall/address", params or None, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def firewall_address_get(
        ctx: Context,
        name: Annotated[str, Field(description="Address object name.")],
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get a specific IPv4 firewall address object."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get(f"firewall/address/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def firewall_address_create(
        ctx: Context,
        name: Annotated[str, Field(description="Address object name.")],
        addr_type: Annotated[
            str,
            Field(
                description="Address type: ipmask, iprange, fqdn, geography, wildcard, mac."
            ),
        ],
        subnet: Annotated[
            str | None,
            Field(
                default=None,
                description="Subnet in CIDR or mask format (e.g. '10.0.0.0/24' or '10.0.0.0 255.255.255.0'). Required for type ipmask.",
            ),
        ] = None,
        fqdn: Annotated[
            str | None,
            Field(default=None, description="FQDN (required for type fqdn)."),
        ] = None,
        start_ip: Annotated[
            str | None,
            Field(default=None, description="Start IP (required for type iprange)."),
        ] = None,
        end_ip: Annotated[
            str | None,
            Field(default=None, description="End IP (required for type iprange)."),
        ] = None,
        country: Annotated[
            str | None,
            Field(
                default=None,
                description="Two-letter country code (required for type geography).",
            ),
        ] = None,
        comment: Annotated[
            str | None, Field(default=None, description="Optional comment.")
        ] = None,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Create a new IPv4 firewall address object."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        body: dict[str, Any] = {"name": name, "type": addr_type}
        if subnet:
            body["subnet"] = subnet
        if fqdn:
            body["fqdn"] = fqdn
        if start_ip:
            body["start-ip"] = start_ip
        if end_ip:
            body["end-ip"] = end_ip
        if country:
            body["country"] = country
        if comment:
            body["comment"] = comment
        try:
            return await client.cmdb_post("firewall/address", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def firewall_address_update(
        ctx: Context,
        name: Annotated[str, Field(description="Address object name to update.")],
        subnet: Annotated[
            str | None, Field(default=None, description="New subnet.")
        ] = None,
        fqdn: Annotated[
            str | None, Field(default=None, description="New FQDN.")
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
        """Update an IPv4 firewall address object."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        body: dict[str, Any] = {}
        if subnet is not None:
            body["subnet"] = subnet
        if fqdn is not None:
            body["fqdn"] = fqdn
        if comment is not None:
            body["comment"] = comment
        if not body:
            return {"error": "No fields to update were specified."}
        try:
            return await client.cmdb_put(f"firewall/address/{name}", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def firewall_address_delete(
        ctx: Context,
        name: Annotated[str, Field(description="Address object name to delete.")],
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Delete an IPv4 firewall address object."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_delete(f"firewall/address/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # ADDRESS GROUPS
    # ==================================================================

    @mcp.tool()
    async def firewall_addrgrp_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List all IPv4 firewall address groups."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("firewall/addrgrp", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def firewall_addrgrp_get(
        ctx: Context,
        name: Annotated[str, Field(description="Address group name.")],
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get a specific IPv4 address group and its members."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get(f"firewall/addrgrp/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def firewall_addrgrp_create(
        ctx: Context,
        name: Annotated[str, Field(description="Address group name.")],
        members: Annotated[
            list[str],
            Field(
                description="List of address or address group names to include as members."
            ),
        ],
        comment: Annotated[
            str | None, Field(default=None, description="Optional comment.")
        ] = None,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Create a new IPv4 address group."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        body: dict[str, Any] = {
            "name": name,
            "member": [{"name": m} for m in members],
        }
        if comment:
            body["comment"] = comment
        try:
            return await client.cmdb_post("firewall/addrgrp", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def firewall_addrgrp_delete(
        ctx: Context,
        name: Annotated[str, Field(description="Address group name to delete.")],
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Delete an IPv4 address group."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_delete(f"firewall/addrgrp/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # SERVICE OBJECTS
    # ==================================================================

    @mcp.tool()
    async def firewall_service_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List all custom firewall service objects."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("firewall.service/custom", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def firewall_service_get(
        ctx: Context,
        name: Annotated[str, Field(description="Service object name.")],
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get a specific custom firewall service object."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get(f"firewall.service/custom/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def firewall_service_create(
        ctx: Context,
        name: Annotated[str, Field(description="Service object name.")],
        protocol: Annotated[
            str, Field(description="Protocol: TCP/UDP/SCTP, ICMP, IP, or ALL.")
        ],
        tcp_portrange: Annotated[
            str | None,
            Field(
                default=None,
                description="TCP port range (e.g. '80', '8080-8090', '80 443').",
            ),
        ] = None,
        udp_portrange: Annotated[
            str | None, Field(default=None, description="UDP port range.")
        ] = None,
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
        """Create a new custom service object."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        body: dict[str, Any] = {"name": name, "protocol": protocol}
        if tcp_portrange:
            body["tcp-portrange"] = tcp_portrange
        if udp_portrange:
            body["udp-portrange"] = udp_portrange
        if comment:
            body["comment"] = comment
        try:
            return await client.cmdb_post("firewall.service/custom", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def firewall_service_grp_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List all firewall service groups."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("firewall.service/group", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # VIRTUAL IPs (VIP)
    # ==================================================================

    @mcp.tool()
    async def firewall_vip_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List all Virtual IP (DNAT) objects."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("firewall/vip", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def firewall_vip_get(
        ctx: Context,
        name: Annotated[str, Field(description="VIP object name.")],
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get a specific Virtual IP (DNAT) object."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get(f"firewall/vip/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def firewall_vip_create(
        ctx: Context,
        name: Annotated[str, Field(description="VIP name.")],
        external_ip: Annotated[
            str, Field(description="External (public) IP address or range.")
        ],
        mapped_ip: Annotated[
            str, Field(description="Internal (mapped) IP address or range.")
        ],
        interface: Annotated[
            str, Field(default="any", description="External interface (default: any).")
        ] = "any",
        portforward: Annotated[
            str,
            Field(
                default="disable",
                description="Enable port forwarding: enable or disable.",
            ),
        ] = "disable",
        external_port: Annotated[
            str | None,
            Field(
                default=None,
                description="External port(s) (e.g. '8080' or '8080-8090').",
            ),
        ] = None,
        mapped_port: Annotated[
            str | None, Field(default=None, description="Internal mapped port(s).")
        ] = None,
        protocol: Annotated[
            str,
            Field(
                default="tcp",
                description="Protocol for port forwarding: tcp, udp, or sctp.",
            ),
        ] = "tcp",
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
        """Create a new Virtual IP (DNAT/port-forward) object."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        body: dict[str, Any] = {
            "name": name,
            "extip": external_ip,
            "mappedip": [{"range": mapped_ip}],
            "extintf": interface,
            "portforward": portforward,
        }
        if portforward == "enable" and external_port:
            body["extport"] = external_port
            body["protocol"] = protocol
            if mapped_port:
                body["mappedport"] = mapped_port
        if comment:
            body["comment"] = comment
        try:
            return await client.cmdb_post("firewall/vip", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def firewall_vip_delete(
        ctx: Context,
        name: Annotated[str, Field(description="VIP name to delete.")],
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Delete a Virtual IP object."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_delete(f"firewall/vip/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # VIP GROUPS
    # ==================================================================

    @mcp.tool()
    async def firewall_vipgrp_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List all VIP groups."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("firewall/vipgrp", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # IP POOLS (source NAT)
    # ==================================================================

    @mcp.tool()
    async def firewall_ippool_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List all IP pool (source NAT) objects."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("firewall/ippool", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def firewall_ippool_create(
        ctx: Context,
        name: Annotated[str, Field(description="IP pool name.")],
        start_ip: Annotated[str, Field(description="Start IP of the NAT pool.")],
        end_ip: Annotated[str, Field(description="End IP of the NAT pool.")],
        pool_type: Annotated[
            str,
            Field(
                default="overload",
                description="NAT pool type: overload, one-to-one, fixed-port-range, port-block-allocation.",
            ),
        ] = "overload",
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
        """Create a new IP pool (source NAT pool) object."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        body: dict[str, Any] = {
            "name": name,
            "startip": start_ip,
            "endip": end_ip,
            "type": pool_type,
        }
        if comment:
            body["comments"] = comment
        try:
            return await client.cmdb_post("firewall/ippool", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # SCHEDULES
    # ==================================================================

    @mcp.tool()
    async def firewall_schedule_one_time_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List all one-time schedules."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("firewall.schedule/onetime", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def firewall_schedule_recurring_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List all recurring schedules."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("firewall.schedule/recurring", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # CENTRAL SNAT
    # ==================================================================

    @mcp.tool()
    async def firewall_central_snat_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List all central SNAT (outgoing NAT) rules."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("firewall/central-snat-map", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # SSL/SSH INSPECTION PROFILES
    # ==================================================================

    @mcp.tool()
    async def firewall_ssl_ssh_profile_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List all SSL/SSH deep inspection profiles."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("firewall/ssl-ssh-profile", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # SHAPING POLICIES
    # ==================================================================

    @mcp.tool()
    async def firewall_shaping_policy_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List all traffic shaping policies."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("firewall/shaping-policy", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # MONITOR: FIREWALL SESSIONS
    # ==================================================================

    @mcp.tool()
    async def monitor_firewall_session_list(
        ctx: Context,
        count: Annotated[
            int, Field(default=100, description="Max number of sessions to return.")
        ] = 100,
        srcaddr: Annotated[
            str | None, Field(default=None, description="Filter by source IP address.")
        ] = None,
        dstaddr: Annotated[
            str | None,
            Field(default=None, description="Filter by destination IP address."),
        ] = None,
        srcport: Annotated[
            int | None, Field(default=None, description="Filter by source port.")
        ] = None,
        dstport: Annotated[
            int | None, Field(default=None, description="Filter by destination port.")
        ] = None,
        protocol: Annotated[
            int | None,
            Field(
                default=None,
                description="Filter by IP protocol number (e.g. 6 for TCP).",
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
        """List active firewall sessions with optional filters."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        params: dict[str, Any] = {"count": count}
        if srcaddr:
            params["srcaddr"] = srcaddr
        if dstaddr:
            params["dstaddr"] = dstaddr
        if srcport is not None:
            params["srcport"] = srcport
        if dstport is not None:
            params["dstport"] = dstport
        if protocol is not None:
            params["proto"] = protocol
        try:
            return await client.monitor_get("firewall/session", params, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def monitor_firewall_session_close(
        ctx: Context,
        proto: Annotated[int, Field(description="IP protocol number (6=TCP, 17=UDP).")],
        srcaddr: Annotated[str, Field(description="Source IP address.")],
        srcport: Annotated[int, Field(description="Source port.")],
        dstaddr: Annotated[str, Field(description="Destination IP address.")],
        dstport: Annotated[int, Field(description="Destination port.")],
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Close a specific active firewall session."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        body = {
            "proto": proto,
            "srcaddr": srcaddr,
            "srcport": srcport,
            "dstaddr": dstaddr,
            "dstport": dstport,
        }
        try:
            return await client.monitor_post("firewall/session/close", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def monitor_firewall_policy_stats(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get hit counts, bytes, and packet statistics per firewall policy."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.monitor_get("firewall/policy-lookup", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def monitor_firewall_address_dynamic(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Get resolved IPs for all dynamic/FQDN firewall address objects."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.monitor_get("firewall/address-dynamic", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def monitor_firewall_ip_list(
        ctx: Context,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """List active banned/exempt IPs in the firewall."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.monitor_get("firewall/iplist", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}
