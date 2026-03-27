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

from fortios_client import FortiOSClient, FortiOSError


def register(mcp: FastMCP) -> None:
    """Register all VPN tools."""

    # ==================================================================
    # IPsec VPN — Phase 1 (Interface mode)
    # ==================================================================

    @mcp.tool()
    async def vpn_ipsec_phase1_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all IPsec VPN Phase 1 (IKE gateway) interfaces."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("vpn.ipsec/phase1-interface", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def vpn_ipsec_phase1_get(
        ctx: Context,
        name: Annotated[str, Field(description="Phase 1 tunnel name.")],
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Get a specific IPsec Phase 1 interface configuration."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get(f"vpn.ipsec/phase1-interface/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def vpn_ipsec_phase1_create(
        ctx: Context,
        name: Annotated[str, Field(description="Tunnel name (unique identifier).")],
        remote_gw: Annotated[str, Field(description="Remote gateway IP address.")],
        interface: Annotated[str, Field(description="Local egress interface (e.g. 'wan1').")],
        psksecret: Annotated[str, Field(description="Pre-shared key.")],
        ike_version: Annotated[
            str, Field(default="2", description="IKE version: 1 or 2.")
        ] = "2",
        mode: Annotated[
            str, Field(default="main", description="IKE mode: main or aggressive (IKEv1 only).")
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
        comments: Annotated[str | None, Field(default=None, description="Comment.")] = None,
        net_device: Annotated[
            str, Field(default="disable", description="Use VPN gateway as network device: enable or disable.")
        ] = "disable",
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Create a new IPsec VPN Phase 1 interface (IKEv1/IKEv2 gateway)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
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

    @mcp.tool()
    async def vpn_ipsec_phase1_update(
        ctx: Context,
        name: Annotated[str, Field(description="Tunnel name to update.")],
        remote_gw: Annotated[str | None, Field(default=None, description="New remote gateway IP.")] = None,
        psksecret: Annotated[str | None, Field(default=None, description="New pre-shared key.")] = None,
        proposal: Annotated[str | None, Field(default=None, description="New Phase 1 proposal.")] = None,
        comments: Annotated[str | None, Field(default=None, description="New comment.")] = None,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Update an existing IPsec Phase 1 interface."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
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
            return await client.cmdb_put(f"vpn.ipsec/phase1-interface/{name}", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def vpn_ipsec_phase1_delete(
        ctx: Context,
        name: Annotated[str, Field(description="Phase 1 tunnel name to delete.")],
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Delete an IPsec Phase 1 tunnel interface."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_delete(f"vpn.ipsec/phase1-interface/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # IPsec VPN — Phase 2
    # ==================================================================

    @mcp.tool()
    async def vpn_ipsec_phase2_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all IPsec VPN Phase 2 (SA / child SA) selectors."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("vpn.ipsec/phase2-interface", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def vpn_ipsec_phase2_get(
        ctx: Context,
        name: Annotated[str, Field(description="Phase 2 selector name.")],
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Get a specific IPsec Phase 2 selector configuration."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get(f"vpn.ipsec/phase2-interface/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def vpn_ipsec_phase2_create(
        ctx: Context,
        name: Annotated[str, Field(description="Phase 2 selector name.")],
        phase1_name: Annotated[str, Field(description="Name of the parent Phase 1 interface.")],
        proposal: Annotated[
            str,
            Field(
                default="aes256-sha256",
                description="Phase 2 encryption/hash proposal (e.g. 'aes256-sha256 aes128-sha256').",
            ),
        ] = "aes256-sha256",
        pfs: Annotated[str, Field(default="enable", description="Perfect Forward Secrecy: enable or disable.")] = "enable",
        dhgrp: Annotated[str, Field(default="14", description="DH group(s) for PFS.")] = "14",
        src_subnet: Annotated[
            str | None,
            Field(default=None, description="Local (source) subnet (e.g. '10.0.0.0/24'). Leave empty for 0.0.0.0/0."),
        ] = None,
        dst_subnet: Annotated[
            str | None,
            Field(default=None, description="Remote (destination) subnet. Leave empty for 0.0.0.0/0."),
        ] = None,
        comments: Annotated[str | None, Field(default=None, description="Comment.")] = None,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Create a new IPsec VPN Phase 2 selector."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
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

    @mcp.tool()
    async def vpn_ipsec_phase2_delete(
        ctx: Context,
        name: Annotated[str, Field(description="Phase 2 selector name to delete.")],
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Delete an IPsec Phase 2 selector."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_delete(f"vpn.ipsec/phase2-interface/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # SSL VPN
    # ==================================================================

    @mcp.tool()
    async def vpn_ssl_settings_get(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Get SSL VPN global settings (port, certificates, idle timeout, etc.)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("vpn.ssl/settings", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def vpn_ssl_settings_update(
        ctx: Context,
        status: Annotated[
            str | None, Field(default=None, description="Enable or disable SSL VPN: enable or disable.")
        ] = None,
        port: Annotated[int | None, Field(default=None, description="SSL VPN listening port (1-65535).")] = None,
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
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Update SSL VPN global settings."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
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

    @mcp.tool()
    async def vpn_ssl_portal_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all SSL VPN portals."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("vpn.ssl.web/portal", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def vpn_ssl_portal_get(
        ctx: Context,
        name: Annotated[str, Field(description="SSL VPN portal name.")],
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Get a specific SSL VPN portal configuration."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get(f"vpn.ssl.web/portal/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def vpn_ssl_portal_create(
        ctx: Context,
        name: Annotated[str, Field(description="Portal name.")],
        tunnel_mode: Annotated[
            str, Field(default="enable", description="Enable tunnel mode: enable or disable.")
        ] = "enable",
        web_mode: Annotated[
            str, Field(default="disable", description="Enable web mode: enable or disable.")
        ] = "disable",
        ip_pools: Annotated[
            list[str] | None,
            Field(default=None, description="IP pool names to assign to tunnel clients."),
        ] = None,
        dns_server1: Annotated[
            str | None, Field(default=None, description="Primary DNS server for clients.")
        ] = None,
        split_tunneling: Annotated[
            str, Field(default="disable", description="Enable split tunneling: enable or disable.")
        ] = "disable",
        heading: Annotated[str | None, Field(default=None, description="Portal heading/title.")] = None,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Create a new SSL VPN portal."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
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

    @mcp.tool()
    async def vpn_ssl_portal_delete(
        ctx: Context,
        name: Annotated[str, Field(description="SSL VPN portal name to delete.")],
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Delete an SSL VPN portal."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_delete(f"vpn.ssl.web/portal/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def vpn_ssl_web_host_check_software_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List SSL VPN host check software (endpoint compliance) rules."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("vpn.ssl.web/host-check-software", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # VPN Certificates
    # ==================================================================

    @mcp.tool()
    async def vpn_certificate_ca_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all VPN CA certificates."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("vpn.certificate/ca", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def vpn_certificate_local_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all VPN local (device) certificates."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("vpn.certificate/local", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def vpn_certificate_remote_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all remote (peer) VPN certificates."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("vpn.certificate/remote", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def vpn_certificate_ocsp_server_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List OCSP server configurations for certificate revocation checking."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("vpn.certificate/ocsp-server", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # Monitor: VPN Status
    # ==================================================================

    @mcp.tool()
    async def monitor_vpn_ipsec(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Get status of all IPsec VPN tunnels (up/down, bytes transferred, SAs)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.monitor_get("vpn/ipsec", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def monitor_vpn_ipsec_tunnel_up(
        ctx: Context,
        tunnel_name: Annotated[str, Field(description="IPsec tunnel (Phase 1) name to bring up.")],
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Bring up (activate) an IPsec VPN tunnel."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.monitor_post("vpn/ipsec/tunnel_up", {"mkey": tunnel_name}, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def monitor_vpn_ipsec_tunnel_down(
        ctx: Context,
        tunnel_name: Annotated[str, Field(description="IPsec tunnel name to bring down.")],
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Bring down (deactivate) an IPsec VPN tunnel."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.monitor_post("vpn/ipsec/tunnel_down", {"mkey": tunnel_name}, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def monitor_vpn_ssl_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List active SSL VPN sessions."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.monitor_get("vpn/ssl", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def monitor_vpn_ssl_delete_user(
        ctx: Context,
        username: Annotated[str, Field(description="SSL VPN username to disconnect.")],
        index: Annotated[
            int | None,
            Field(default=None, description="Session index (use if multiple sessions for same user)."),
        ] = None,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Terminate (disconnect) an active SSL VPN user session."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        body: dict[str, Any] = {"username": username}
        if index is not None:
            body["index"] = index
        try:
            return await client.monitor_post("vpn/ssl/delete", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def monitor_vpn_certificate_valid(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Check validity status of all VPN-related certificates."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.monitor_get("vpn-certificate/cert", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}
