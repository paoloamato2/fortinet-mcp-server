"""VPN configuration and monitoring tools.

Covers:
- /api/v2/cmdb/vpn.ipsec/…    — IPsec VPN Phase 1 & Phase 2
- /api/v2/cmdb/vpn.ssl/…      — SSL VPN settings, portals, server
- /api/v2/cmdb/vpn.certificate/… — VPN certificates
- /api/v2/monitor/vpn/…       — VPN status and operations
"""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP, Context
from pydantic import Field

from fortios_client import FortiOSError
from instances import FortiOSAPI
from resources import VpnResource
from tool_annotations import CREATES, DESTRUCTIVE, READ_ONLY, UPDATES
from tool_params import CountParam, InstanceParam, StartParam, VdomParam
from tools._read import read_resource, resource_table_doc


def register(mcp: FastMCP) -> None:
    """Register all VPN tools."""

    async def vpn_read(
        ctx: Context,
        resource: Annotated[
            VpnResource, Field(description="Which vpn resource to read.")
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
            ctx, "vpn", resource, name, instance, vdom, start, count
        )

    vpn_read.__doc__ = (
        "Read IPsec and SSL-VPN configuration, certificates and tunnel "
        "state.\n\n"
        "Omit `name` to list a resource, or pass it to fetch one object by "
        "key.\n\n" + resource_table_doc("vpn")
    )
    mcp.tool(annotations=READ_ONLY)(vpn_read)

    # ==================================================================
    # IPsec VPN — Phase 1 (Interface mode)
    # ==================================================================

    @mcp.tool(annotations=CREATES)
    async def vpn_ipsec_phase1_create(
        ctx: Context,
        name: Annotated[str, Field(description="Tunnel name (unique identifier).")],
        remote_gw: Annotated[str, Field(description="Remote gateway IP address.")],
        interface: Annotated[
            str, Field(description="Local egress interface (e.g. 'wan1').")
        ],
        psksecret: Annotated[str, Field(description="Pre-shared key.")],
        ike_version: Annotated[
            str, Field(default="2", description="IKE version: 1 or 2.")
        ] = "2",
        mode: Annotated[
            str,
            Field(
                default="main", description="IKE mode: main or aggressive (IKEv1 only)."
            ),
        ] = "main",
        proposal: Annotated[
            str,
            Field(
                default="aes256-sha256",
                description="Phase 1 proposal (cipher-hash). E.g. 'aes256-sha256 aes128-sha256'.",
            ),
        ] = "aes256-sha256",
        dhgrp: Annotated[
            str, Field(default="14", description="DH group(s). E.g. '14 5 2'.")
        ] = "14",
        comments: Annotated[
            str | None, Field(default=None, description="Comment.")
        ] = None,
        net_device: Annotated[
            str,
            Field(
                default="disable",
                description="Use VPN gateway as network device: enable or disable.",
            ),
        ] = "disable",
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Create a new IPsec VPN Phase 1 interface (IKEv1/IKEv2 gateway)."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        body: dict[str, Any] = {
            "name": name,
            "remote-gw": remote_gw,
            "interface": interface,
            "psksecret": psksecret,
            "ike-version": ike_version,
            "mode": mode,
            "proposal": proposal,
            "dhgrp": dhgrp,
            "net-device": net_device,
            "type": "static",
        }
        if comments:
            body["comments"] = comments
        try:
            return await client.cmdb_post("vpn.ipsec/phase1-interface", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=DESTRUCTIVE)
    async def vpn_ipsec_phase1_update(
        ctx: Context,
        name: Annotated[str, Field(description="Tunnel name to update.")],
        remote_gw: Annotated[
            str | None, Field(default=None, description="New remote gateway IP.")
        ] = None,
        psksecret: Annotated[
            str | None, Field(default=None, description="New pre-shared key.")
        ] = None,
        proposal: Annotated[
            str | None, Field(default=None, description="New Phase 1 proposal.")
        ] = None,
        comments: Annotated[
            str | None, Field(default=None, description="New comment.")
        ] = None,
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Update an existing IPsec Phase 1 interface."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        body: dict[str, Any] = {}
        if remote_gw is not None:
            body["remote-gw"] = remote_gw
        if psksecret is not None:
            body["psksecret"] = psksecret
        if proposal is not None:
            body["proposal"] = proposal
        if comments is not None:
            body["comments"] = comments
        if not body:
            return {"error": "No fields to update were specified."}
        try:
            return await client.cmdb_put(
                f"vpn.ipsec/phase1-interface/{name}", body, vdom=vdom
            )
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # IPsec VPN — Phase 2
    # ==================================================================

    @mcp.tool(annotations=CREATES)
    async def vpn_ipsec_phase2_create(
        ctx: Context,
        name: Annotated[str, Field(description="Phase 2 selector name.")],
        phase1_name: Annotated[
            str, Field(description="Name of the parent Phase 1 interface.")
        ],
        proposal: Annotated[
            str,
            Field(
                default="aes256-sha256",
                description="Phase 2 encryption/hash proposal (e.g. 'aes256-sha256 aes128-sha256').",
            ),
        ] = "aes256-sha256",
        pfs: Annotated[
            str,
            Field(
                default="enable",
                description="Perfect Forward Secrecy: enable or disable.",
            ),
        ] = "enable",
        dhgrp: Annotated[
            str, Field(default="14", description="DH group(s) for PFS.")
        ] = "14",
        src_subnet: Annotated[
            str | None,
            Field(
                default=None,
                description="Local (source) subnet (e.g. '10.0.0.0/24'). Leave empty for 0.0.0.0/0.",
            ),
        ] = None,
        dst_subnet: Annotated[
            str | None,
            Field(
                default=None,
                description="Remote (destination) subnet. Leave empty for 0.0.0.0/0.",
            ),
        ] = None,
        comments: Annotated[
            str | None, Field(default=None, description="Comment.")
        ] = None,
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Create a new IPsec VPN Phase 2 selector."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        body: dict[str, Any] = {
            "name": name,
            "phase1name": phase1_name,
            "proposal": proposal,
            "pfs": pfs,
            "dhgrp": dhgrp,
        }
        if src_subnet:
            parts = src_subnet.replace("/", " ").split()
            body["src-addr-type"] = "subnet"
            body["src-start-ip"] = parts[0]
            if len(parts) > 1:
                body["src-end-ip"] = parts[1]
        if dst_subnet:
            parts = dst_subnet.replace("/", " ").split()
            body["dst-addr-type"] = "subnet"
            body["dst-start-ip"] = parts[0]
            if len(parts) > 1:
                body["dst-end-ip"] = parts[1]
        if comments:
            body["comments"] = comments
        try:
            return await client.cmdb_post("vpn.ipsec/phase2-interface", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # SSL VPN
    # ==================================================================

    @mcp.tool(annotations=DESTRUCTIVE)
    async def vpn_ssl_settings_update(
        ctx: Context,
        status: Annotated[
            str | None,
            Field(
                default=None,
                description="Enable or disable SSL VPN: enable or disable.",
            ),
        ] = None,
        port: Annotated[
            int | None,
            Field(default=None, description="SSL VPN listening port (1-65535)."),
        ] = None,
        servercert: Annotated[
            str | None, Field(default=None, description="Server certificate name.")
        ] = None,
        idle_timeout: Annotated[
            int | None,
            Field(default=None, description="Idle connection timeout in seconds."),
        ] = None,
        login_attempts_limit: Annotated[
            int | None,
            Field(default=None, description="Max login failures before lockout."),
        ] = None,
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Update SSL VPN global settings."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        body: dict[str, Any] = {}
        if status is not None:
            body["status"] = status
        if port is not None:
            body["port"] = port
        if servercert is not None:
            body["servercert"] = servercert
        if idle_timeout is not None:
            body["idle-timeout"] = idle_timeout
        if login_attempts_limit is not None:
            body["login-attempt-limit"] = login_attempts_limit
        if not body:
            return {"error": "No fields to update were specified."}
        try:
            return await client.cmdb_put("vpn.ssl/settings", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=CREATES)
    async def vpn_ssl_portal_create(
        ctx: Context,
        name: Annotated[str, Field(description="Portal name.")],
        tunnel_mode: Annotated[
            str,
            Field(
                default="enable", description="Enable tunnel mode: enable or disable."
            ),
        ] = "enable",
        web_mode: Annotated[
            str,
            Field(default="disable", description="Enable web mode: enable or disable."),
        ] = "disable",
        ip_pools: Annotated[
            list[str] | None,
            Field(
                default=None, description="IP pool names to assign to tunnel clients."
            ),
        ] = None,
        dns_server1: Annotated[
            str | None,
            Field(default=None, description="Primary DNS server for clients."),
        ] = None,
        split_tunneling: Annotated[
            str,
            Field(
                default="disable",
                description="Enable split tunneling: enable or disable.",
            ),
        ] = "disable",
        heading: Annotated[
            str | None, Field(default=None, description="Portal heading/title.")
        ] = None,
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Create a new SSL VPN portal."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        body: dict[str, Any] = {
            "name": name,
            "tunnel-mode": tunnel_mode,
            "web-mode": web_mode,
            "split-tunneling": split_tunneling,
        }
        if ip_pools:
            body["ip-pools"] = [{"name": p} for p in ip_pools]
        if dns_server1:
            body["dns-server1"] = dns_server1
        if heading:
            body["heading"] = heading
        try:
            return await client.cmdb_post("vpn.ssl.web/portal", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # Monitor: VPN Status
    # ==================================================================

    @mcp.tool(annotations=UPDATES)
    async def monitor_vpn_ipsec_tunnel_up(
        ctx: Context,
        tunnel_name: Annotated[
            str, Field(description="IPsec tunnel (Phase 1) name to bring up.")
        ],
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Bring up (activate) an IPsec VPN tunnel."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.monitor_post(
                "vpn/ipsec/tunnel_up", {"mkey": tunnel_name}, vdom=vdom
            )
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=DESTRUCTIVE)
    async def monitor_vpn_ipsec_tunnel_down(
        ctx: Context,
        tunnel_name: Annotated[
            str, Field(description="IPsec tunnel name to bring down.")
        ],
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Bring down (deactivate) an IPsec VPN tunnel."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.monitor_post(
                "vpn/ipsec/tunnel_down", {"mkey": tunnel_name}, vdom=vdom
            )
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=DESTRUCTIVE)
    async def monitor_vpn_ssl_delete_user(
        ctx: Context,
        username: Annotated[str, Field(description="SSL VPN username to disconnect.")],
        index: Annotated[
            int | None,
            Field(
                default=None,
                description="Session index (use if multiple sessions for same user).",
            ),
        ] = None,
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Terminate (disconnect) an active SSL VPN user session."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        body: dict[str, Any] = {"username": username}
        if index is not None:
            body["index"] = index
        try:
            return await client.monitor_post("vpn/ssl/delete", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}
