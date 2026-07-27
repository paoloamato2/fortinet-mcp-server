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
from tool_annotations import CREATES, DESTRUCTIVE, READ_ONLY


def register(mcp: FastMCP) -> None:
    """Register all wireless tools."""

    # ==================================================================
    # WTP PROFILES (AP Profiles)
    # ==================================================================

    @mcp.tool(annotations=READ_ONLY)
    async def wifi_wtp_profile_list(
        ctx: Context,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """List all WTP (Wireless Termination Point / AP) profiles."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.cmdb_get("wireless-controller/wtp-profile", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=READ_ONLY)
    async def wifi_wtp_profile_get(
        ctx: Context,
        name: Annotated[str, Field(description="WTP profile name.")],
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Get a specific AP (WTP) profile configuration."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.cmdb_get(
                f"wireless-controller/wtp-profile/{name}", vdom=vdom
            )
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # WTP (Access Points)
    # ==================================================================

    @mcp.tool(annotations=READ_ONLY)
    async def wifi_wtp_list(
        ctx: Context,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """List all registered WTPs (Access Points) with their configuration."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.cmdb_get("wireless-controller/wtp", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=READ_ONLY)
    async def wifi_wtp_get(
        ctx: Context,
        wtp_id: Annotated[str, Field(description="WTP (AP) serial number or name.")],
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Get configuration for a specific WTP (Access Point)."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.cmdb_get(f"wireless-controller/wtp/{wtp_id}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # DESTRUCTIVE, not an operational deauth: this is a cmdb_delete that
    # removes the WTP configuration entry.
    @mcp.tool(annotations=DESTRUCTIVE)
    async def wifi_wtp_deauthorize(
        ctx: Context,
        wtp_id: Annotated[str, Field(description="WTP serial number to deauthorize.")],
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Deauthorize (remove) a WTP (Access Point) from the controller."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.cmdb_delete(
                f"wireless-controller/wtp/{wtp_id}", vdom=vdom
            )
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # VAP (Virtual AP / SSID)
    # ==================================================================

    @mcp.tool(annotations=READ_ONLY)
    async def wifi_vap_list(
        ctx: Context,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """List all VAPs (Virtual APs / SSIDs)."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.cmdb_get("wireless-controller/vap", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=READ_ONLY)
    async def wifi_vap_get(
        ctx: Context,
        name: Annotated[str, Field(description="VAP (SSID) name.")],
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Get a specific VAP (SSID) configuration."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.cmdb_get(f"wireless-controller/vap/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

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
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
            ),
        ] = None,
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

    @mcp.tool(annotations=DESTRUCTIVE)
    async def wifi_vap_delete(
        ctx: Context,
        name: Annotated[str, Field(description="VAP (SSID) name to delete.")],
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Delete a VAP (SSID) wireless network."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.cmdb_delete(
                f"wireless-controller/vap/{name}", vdom=vdom
            )
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # VAP GROUPS
    # ==================================================================

    @mcp.tool(annotations=READ_ONLY)
    async def wifi_vap_group_list(
        ctx: Context,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """List all VAP groups (SSID bundles)."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.cmdb_get("wireless-controller/vap-group", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # WIRELESS CONTROLLER GLOBAL
    # ==================================================================

    @mcp.tool(annotations=READ_ONLY)
    async def wifi_controller_setting_get(
        ctx: Context,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Get wireless controller global settings."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.cmdb_get("wireless-controller/setting", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=READ_ONLY)
    async def wifi_qos_profile_list(
        ctx: Context,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """List all wireless QoS profiles."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.cmdb_get("wireless-controller/qos-profile", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=READ_ONLY)
    async def wifi_rf_analysis_get(
        ctx: Context,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Get wireless RF analysis settings."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.cmdb_get("wireless-controller/rf-analysis", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # HOTSPOT 2.0
    # ==================================================================

    @mcp.tool(annotations=READ_ONLY)
    async def wifi_hotspot20_profile_list(
        ctx: Context,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """List all Hotspot 2.0 (Passpoint) profiles."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.cmdb_get(
                "wireless-controller.hotspot20/hs-profile", vdom=vdom
            )
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # MONITOR: WiFi Status
    # ==================================================================

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_wifi_managed_ap(
        ctx: Context,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Get detailed status of all managed Access Points (online/offline, channel, clients)."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.monitor_get("wifi/managed_ap", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

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
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
    async def monitor_wifi_rogue_ap(
        ctx: Context,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Get list of detected rogue (unauthorized) Access Points."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.monitor_get("wifi/rogue_ap", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_wifi_spectrum_analysis(
        ctx: Context,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Get RF spectrum analysis data from APs that support it."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.monitor_get("wifi/spectrum", vdom=vdom)
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
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_wifi_interfering_ap(
        ctx: Context,
        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
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
        """Get list of interfering (neighbor) Access Points detected on RF scan."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.monitor_get("wifi/interfering_ap", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}
