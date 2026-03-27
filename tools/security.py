"""Security profile tools — IPS, Antivirus, WebFilter, App Control, DLP, etc.

Covers /api/v2/cmdb/ips/…, /api/v2/cmdb/antivirus/…, /api/v2/cmdb/webfilter/…,
/api/v2/cmdb/application/…, /api/v2/cmdb/dlp/…, /api/v2/cmdb/emailfilter/…,
/api/v2/cmdb/voip/…, /api/v2/cmdb/icap/…, /api/v2/cmdb/dnsfilter/…,
/api/v2/cmdb/ssh-filter/…, /api/v2/cmdb/virtual-patch/…
"""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP, Context
from pydantic import Field

from fortios_client import FortiOSClient, FortiOSError


def register(mcp: FastMCP) -> None:
    """Register all security profile tools."""

    # ==================================================================
    # IPS (Intrusion Prevention System)
    # ==================================================================

    @mcp.tool()
    async def ips_sensor_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all IPS sensor profiles."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("ips/sensor", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def ips_sensor_get(
        ctx: Context,
        name: Annotated[str, Field(description="IPS sensor name.")],
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Get a specific IPS sensor profile."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get(f"ips/sensor/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def ips_sensor_create(
        ctx: Context,
        name: Annotated[str, Field(description="IPS sensor name.")],
        block_malicious_url: Annotated[
            str, Field(default="disable", description="Block malicious URLs: enable or disable.")
        ] = "disable",
        comment: Annotated[str | None, Field(default=None, description="Comment.")] = None,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Create a new IPS sensor profile."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        body: dict[str, Any] = {
            "name": name,
            "block-malicious-url": block_malicious_url,
        }
        if comment:
            body["comment"] = comment
        try:
            return await client.cmdb_post("ips/sensor", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def ips_sensor_delete(
        ctx: Context,
        name: Annotated[str, Field(description="IPS sensor name to delete.")],
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Delete an IPS sensor profile."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_delete(f"ips/sensor/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def ips_custom_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all custom IPS signatures."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("ips/custom", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # ANTIVIRUS
    # ==================================================================

    @mcp.tool()
    async def antivirus_profile_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all antivirus profiles."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("antivirus/profile", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def antivirus_profile_get(
        ctx: Context,
        name: Annotated[str, Field(description="Antivirus profile name.")],
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Get a specific antivirus profile."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get(f"antivirus/profile/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def antivirus_profile_create(
        ctx: Context,
        name: Annotated[str, Field(description="Profile name.")],
        comment: Annotated[str | None, Field(default=None, description="Comment.")] = None,
        ftgd_analytics: Annotated[
            str, Field(default="disable", description="FortiSandbox analytics: disable, suspicious, or all.")
        ] = "disable",
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Create a new antivirus profile."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        body: dict[str, Any] = {"name": name, "ftgd-analytics": ftgd_analytics}
        if comment:
            body["comment"] = comment
        try:
            return await client.cmdb_post("antivirus/profile", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def antivirus_settings_get(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Get antivirus engine settings (scan cache, exclusions)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("antivirus/settings", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # WEBFILTER
    # ==================================================================

    @mcp.tool()
    async def webfilter_profile_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all web filter profiles."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("webfilter/profile", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def webfilter_profile_get(
        ctx: Context,
        name: Annotated[str, Field(description="Web filter profile name.")],
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Get a specific web filter profile."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get(f"webfilter/profile/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def webfilter_urlfilter_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all URL filter tables (custom URL block/allow lists)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("webfilter/urlfilter", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def webfilter_override_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all web filter category override rules."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("webfilter/override", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def webfilter_content_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all web content filter (keyword) tables."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("webfilter/content", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # APPLICATION CONTROL
    # ==================================================================

    @mcp.tool()
    async def application_list_profiles(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all Application Control profiles."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("application/list", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def application_list_get(
        ctx: Context,
        name: Annotated[str, Field(description="Application profile name.")],
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Get a specific Application Control profile."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get(f"application/list/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def application_group_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all application groups."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("application/group", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # DLP (Data Loss Prevention)
    # ==================================================================

    @mcp.tool()
    async def dlp_sensor_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all DLP sensors."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("dlp/sensor", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def dlp_dictionary_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all DLP data dictionaries."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("dlp/dictionary", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def dlp_filepattern_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all DLP file pattern tables."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("dlp/filepattern", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # EMAIL FILTER
    # ==================================================================

    @mcp.tool()
    async def emailfilter_profile_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all email filter profiles."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("emailfilter/profile", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def emailfilter_bwl_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List email filter block/allow lists."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("emailfilter/bwl", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # DNS FILTER
    # ==================================================================

    @mcp.tool()
    async def dnsfilter_profile_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all DNS filter profiles."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("dnsfilter/profile", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def dnsfilter_domain_filter_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List DNS domain filter tables (custom domain block/allow)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("dnsfilter/domain-filter", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # FILE FILTER
    # ==================================================================

    @mcp.tool()
    async def file_filter_profile_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all file filter profiles."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("file-filter/profile", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # ICAP
    # ==================================================================

    @mcp.tool()
    async def icap_server_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all ICAP server configurations."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("icap/server", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def icap_profile_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all ICAP profiles."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("icap/profile", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # SSH FILTER
    # ==================================================================

    @mcp.tool()
    async def ssh_filter_profile_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all SSH filter profiles."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("ssh-filter/profile", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # WAF (Web Application Firewall)
    # ==================================================================

    @mcp.tool()
    async def waf_profile_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all WAF profiles."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("waf/profile", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def waf_signature_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all WAF signature configurations."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("waf/signature", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # VOIP
    # ==================================================================

    @mcp.tool()
    async def voip_profile_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all VoIP (SIP/SCCP) inspection profiles."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("voip/profile", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # VIRTUAL PATCH
    # ==================================================================

    @mcp.tool()
    async def virtual_patch_profile_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all Virtual Patch profiles (inline IPS pre-patching)."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("virtual-patch/profile", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # AUTOMATION (FortiOS Automation Stitches)
    # ==================================================================

    @mcp.tool()
    async def automation_setting_get(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """Get global automation settings."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("automation/setting", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # ZTNA (Zero Trust Network Access)
    # ==================================================================

    @mcp.tool()
    async def ztna_server_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all ZTNA access proxy (application gateway) servers."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("ztna/proxy", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool()
    async def ztna_tag_policy_list(
        ctx: Context,
        vdom: Annotated[str | None, Field(default=None, description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).")] = None,
    ) -> dict[str, Any]:
        """List all ZTNA EMS tag (posture check) policies."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            return await client.cmdb_get("ztna/ems-tag", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}
