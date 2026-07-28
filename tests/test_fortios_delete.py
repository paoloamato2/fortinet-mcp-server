"""Behaviour and safety of the consolidated delete tool.

Replaces 15 aliases that each wrapped one ``cmdb_delete`` call. The enum is
the point: FastMCP validates ``Literal`` before the body runs, so this tool
cannot be pointed at an arbitrary path the way ``cmdb_delete`` can.
"""

from __future__ import annotations

from typing import Any

import pytest

from fortios_client import FortiOSError
from resources import DELETE_RESOURCES


class FakeClient:
    def __init__(self, raises: FortiOSError | None = None) -> None:
        self.calls: list[tuple[str, str | None]] = []
        self._raises = raises

    async def cmdb_delete(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        self.calls.append((path, vdom))
        if self._raises:
            raise self._raises
        return {"status": "success", "path": path}


class FakeContext:
    def __init__(self, client: FakeClient) -> None:
        class _Registry:
            def resolve(self, _instance: str | None) -> FakeClient:
                return client

        class _RequestContext:
            lifespan_context = {"registry": _Registry()}

        self.request_context = _RequestContext()

    async def error(self, _message: str) -> None:
        return None


def _delete_tool():
    """The registered ``fortios_delete`` callable, via the tool manager."""
    from server import mcp

    tool = mcp._tool_manager.get_tool("fortios_delete")
    assert tool is not None, "fortios_delete is not registered"
    return tool.fn


async def test_builds_the_keyed_path() -> None:
    client = FakeClient()
    result = await _delete_tool()(
        FakeContext(client), resource="firewall_address", name="stale-host"
    )
    assert client.calls == [("firewall/address/stale-host", None)]
    assert "error" not in result


async def test_vdom_is_passed_through() -> None:
    client = FakeClient()
    await _delete_tool()(
        FakeContext(client), resource="user_local", name="bob", vdom="root"
    )
    assert client.calls == [("user/local/bob", "root")]


async def test_fortios_error_is_returned_as_a_dict() -> None:
    client = FakeClient(raises=FortiOSError("in use by policy 7", status_code=424))
    result = await _delete_tool()(
        FakeContext(client), resource="firewall_address", name="x"
    )
    assert result["status_code"] == 424
    assert "in use by policy 7" in result["error"]


async def test_every_table_row_is_reachable() -> None:
    """Each enum value maps to a row, so none is dead."""
    for value in DELETE_RESOURCES:
        client = FakeClient()
        await _delete_tool()(FakeContext(client), resource=value, name="probe")
        assert client.calls, f"{value} issued no call"
        assert client.calls[0][0].endswith("/probe")


async def test_the_enum_rejects_an_arbitrary_path() -> None:
    """The safety property: this tool cannot be aimed anywhere it likes."""
    from mcp.server.fastmcp.exceptions import ToolError
    from server import mcp

    with pytest.raises(ToolError) as excinfo:
        await mcp.call_tool(
            "fortios_delete",
            {"resource": "system/admin/../../etc", "name": "x"},
        )
    assert "resource" in str(excinfo.value)


async def test_it_advertises_destructive() -> None:
    from server import mcp

    tools = {t.name: t for t in await mcp.list_tools()}
    ann = tools["fortios_delete"].annotations
    assert ann is not None
    assert ann.readOnlyHint is False
    assert ann.destructiveHint is True
    assert (
        len(tools["fortios_delete"].inputSchema["properties"]["resource"]["enum"]) == 15
    )


@pytest.mark.parametrize(
    "removed",
    [
        "firewall_policy_delete",
        "firewall_address_delete",
        "firewall_addrgrp_delete",
        "firewall_vip_delete",
        "router_static_delete",
        "ips_sensor_delete",
        "system_interface_delete",
        "system_admin_delete",
        "user_local_delete",
        "user_group_delete",
        "vpn_ipsec_phase1_delete",
        "vpn_ipsec_phase2_delete",
        "vpn_ssl_portal_delete",
        "wifi_wtp_deauthorize",
        "wifi_vap_delete",
    ],
)
async def test_the_replaced_delete_tools_are_gone(removed: str) -> None:
    from server import mcp

    names = {t.name for t in await mcp.list_tools()}
    assert removed not in names
