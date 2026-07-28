"""Wireless controller and WiFi monitoring tools.

Covers /api/v2/cmdb/wireless-controller/…,
/api/v2/cmdb/wireless-controller.hotspot20/…,
and /api/v2/monitor/wifi/…
"""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP, Context
from pydantic import Field

from fortios_client import FortiOSError
from instances import FortiOSAPI
from resources import WirelessResource
from tool_annotations import CREATES, READ_ONLY
from tool_params import CountParam, InstanceParam, StartParam, VdomParam
from tools._read import read_resource, resource_table_doc


def register(mcp: FastMCP) -> None:
    """Register all wireless tools."""

    async def wireless_read(
        ctx: Context,
        resource: Annotated[
            WirelessResource, Field(description="Which wireless resource to read.")
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
            ctx, "wireless", resource, name, instance, vdom, start, count
        )

    wireless_read.__doc__ = (
        "Read wireless controller configuration and live AP/client state.\n\n"
        "Omit `name` to list a resource, or pass it to fetch one object by "
        "key.\n\n" + resource_table_doc("wireless")
    )
    mcp.tool(annotations=READ_ONLY)(wireless_read)

    # ==================================================================
    # WTP (Access Points)
    # ==================================================================

    # ==================================================================
    # VAP (Virtual AP / SSID)
    # ==================================================================

    @mcp.tool(annotations=CREATES)
    async def wifi_vap_create(
        ctx: Context,
        name: Annotated[str, Field(description="SSID name.")],
        ssid: Annotated[
            str, Field(description="Wireless network SSID broadcast name.")
        ],
        security: Annotated[
            str,
            Field(
                default="wpa2-only-personal",
                description=(
                    "Security mode: open, captive-portal, wpa-only-personal, wpa2-only-personal, "
                    "wpa-personal, wpa-only-enterprise, wpa2-only-enterprise, wpa-enterprise."
                ),
            ),
        ] = "wpa2-only-personal",
        passphrase: Annotated[
            str | None,
            Field(
                default=None, description="WPA/WPA2 pre-shared key (8-63 characters)."
            ),
        ] = None,
        instance: InstanceParam = None,
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="VDOM name for this VAP and for routing the API request.",
            ),
        ] = None,
        broadcast_ssid: Annotated[
            str,
            Field(default="enable", description="Broadcast SSID: enable or disable."),
        ] = "enable",
        fast_bss_transition: Annotated[
            str,
            Field(
                default="disable",
                description="802.11r Fast BSS Transition: enable or disable.",
            ),
        ] = "disable",
    ) -> dict[str, Any]:
        """Create a new VAP (SSID) wireless network."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        body: dict[str, Any] = {
            "name": name,
            "ssid": ssid,
            "security": security,
            "broadcast-ssid": broadcast_ssid,
            "fast-bss-transition": fast_bss_transition,
        }
        if passphrase:
            body["passphrase"] = passphrase
        if vdom:
            body["vdom"] = vdom
        try:
            return await client.cmdb_post("wireless-controller/vap", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # MONITOR: WiFi Status
    # ==================================================================

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_wifi_client_list(
        ctx: Context,
        ap_serial: Annotated[
            str | None,
            Field(default=None, description="Filter by Access Point serial number."),
        ] = None,
        ssid: Annotated[
            str | None,
            Field(default=None, description="Filter by SSID name."),
        ] = None,
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """List all connected WiFi clients with their associated AP and signal strength."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        params: dict[str, Any] = {}
        if ap_serial:
            params["wtp"] = ap_serial
        if ssid:
            params["ssid"] = ssid
        try:
            return await client.monitor_get("wifi/client", params or None, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_wifi_ap_status(
        ctx: Context,
        wtp_id: Annotated[
            str | None,
            Field(
                default=None,
                description="AP serial number. If not specified, returns all APs.",
            ),
        ] = None,
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Get operational status (up/down, channel, TX power) for APs."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        params: dict[str, Any] = {}
        if wtp_id:
            params["wtp_id"] = wtp_id
        try:
            return await client.monitor_get("wifi/ap_status", params or None, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}
