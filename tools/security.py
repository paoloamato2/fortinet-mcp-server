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

from fortios_client import FortiOSError
from instances import FortiOSAPI
from resources import SecurityResource
from tool_annotations import CREATES, READ_ONLY
from tool_params import InstanceParam, VdomParam
from tools._read import read_resource, resource_table_doc


def register(mcp: FastMCP) -> None:
    """Register all security profile tools."""

    async def security_read(
        ctx: Context,
        resource: Annotated[
            SecurityResource, Field(description="Which security resource to read.")
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
        return await read_resource(ctx, "security", resource, name, instance, vdom)

    security_read.__doc__ = (
        "Read security profiles: IPS, antivirus, web filter, DLP, WAF, "
        "ZTNA.\n\n"
        "Omit `name` to list a resource, or pass it to fetch one object by "
        "key.\n\n" + resource_table_doc("security")
    )
    mcp.tool(annotations=READ_ONLY)(security_read)

    # ==================================================================
    # IPS (Intrusion Prevention System)
    # ==================================================================

    @mcp.tool(annotations=CREATES)
    async def ips_sensor_create(
        ctx: Context,
        name: Annotated[str, Field(description="IPS sensor name.")],
        block_malicious_url: Annotated[
            str,
            Field(
                default="disable",
                description="Block malicious URLs: enable or disable.",
            ),
        ] = "disable",
        comment: Annotated[
            str | None, Field(default=None, description="Comment.")
        ] = None,
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Create a new IPS sensor profile."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
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

    # ==================================================================
    # ANTIVIRUS
    # ==================================================================

    @mcp.tool(annotations=CREATES)
    async def antivirus_profile_create(
        ctx: Context,
        name: Annotated[str, Field(description="Profile name.")],
        comment: Annotated[
            str | None, Field(default=None, description="Comment.")
        ] = None,
        ftgd_analytics: Annotated[
            str,
            Field(
                default="disable",
                description="FortiSandbox analytics: disable, suspicious, or all.",
            ),
        ] = "disable",
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Create a new antivirus profile."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        body: dict[str, Any] = {"name": name, "ftgd-analytics": ftgd_analytics}
        if comment:
            body["comment"] = comment
        try:
            return await client.cmdb_post("antivirus/profile", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}
