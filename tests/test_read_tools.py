"""Behaviour of the per-domain read tools.

These replace 145 tools whose bodies were one client call with a hardcoded
path. What has to hold: the right path is built for a list and for a keyed
read, singletons refuse a key rather than 404ing, and FortiOSError still
comes back as a dict instead of propagating.
"""

from __future__ import annotations

from typing import Any, cast

import pytest
from mcp.server.fastmcp import Context

from fortios_client import FortiOSError
from tools._read import read_resource, resource_table_doc


class FakeClient:
    """Records the calls a tool makes instead of reaching a FortiGate."""

    def __init__(self, raises: FortiOSError | None = None) -> None:
        self.calls: list[tuple[str, str, str | None]] = []
        self._raises = raises

    async def cmdb_get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        self.calls.append(("cmdb_get", path, vdom))
        if self._raises:
            raise self._raises
        return {"results": [], "path": path}

    async def monitor_get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        self.calls.append(("monitor_get", path, vdom))
        if self._raises:
            raise self._raises
        return {"results": [], "path": path}


class FakeContext:
    """Minimal stand-in for the MCP ``Context`` a tool receives."""

    def __init__(self, client: FakeClient) -> None:
        class _Registry:
            def resolve(self, _instance: str | None) -> FakeClient:
                return client

        class _RequestContext:
            lifespan_context = {"registry": _Registry()}

        self.request_context = _RequestContext()

    async def error(self, _message: str) -> None:
        return None


def _ctx(client: FakeClient) -> Context:
    """Type-erase ``FakeContext`` to the ``Context`` a tool declares.

    ``FakeContext`` is a structural stand-in, not a subclass of pydantic's
    ``Context`` model, so this cast is the one place that acknowledges that
    on purpose rather than a ``# type: ignore`` on every call site below.
    """
    return cast(Context, FakeContext(client))


async def test_list_read_builds_the_bare_path() -> None:
    client = FakeClient()
    result = await read_resource(_ctx(client), "user", "local", None, None, None)
    assert client.calls == [("cmdb_get", "user/local", None)]
    assert "error" not in result


async def test_keyed_read_appends_the_name() -> None:
    client = FakeClient()
    await read_resource(_ctx(client), "user", "local", "alice", None, None)
    assert client.calls == [("cmdb_get", "user/local/alice", None)]


async def test_monitor_resource_dispatches_to_monitor_get() -> None:
    client = FakeClient()
    await read_resource(_ctx(client), "user", "fortitoken", None, None, None)
    assert client.calls == [("monitor_get", "user/fortitoken", None)]


async def test_vdom_is_passed_through() -> None:
    client = FakeClient()
    await read_resource(_ctx(client), "user", "local", None, None, "root")
    assert client.calls == [("cmdb_get", "user/local", "root")]


async def test_name_on_a_singleton_is_refused_without_calling_the_device() -> None:
    client = FakeClient()
    result = await read_resource(
        _ctx(client), "system", "global", "anything", None, None
    )
    assert client.calls == [], "a refused call must not reach the FortiGate"
    assert "error" in result
    assert "singleton" in result["error"]
    assert "global" in result["error"]


async def test_name_on_a_monitor_resource_is_refused() -> None:
    client = FakeClient()
    result = await read_resource(_ctx(client), "user", "fortitoken", "x", None, None)
    assert client.calls == []
    assert "error" in result


async def test_unknown_resource_is_reported_not_raised() -> None:
    """Pydantic blocks this at the schema, but the helper is defensive."""
    client = FakeClient()
    result = await read_resource(_ctx(client), "user", "nope", None, None, None)
    assert client.calls == []
    assert "error" in result


async def test_fortios_error_is_returned_as_a_dict() -> None:
    client = FakeClient(raises=FortiOSError("permission denied", status_code=403))
    result = await read_resource(_ctx(client), "user", "local", None, None, None)
    assert result["status_code"] == 403
    assert "permission denied" in result["error"]


def test_table_doc_lists_every_resource_with_its_summary() -> None:
    doc = resource_table_doc("user")
    assert "`local`" in doc
    assert "List all local user accounts." in doc
    assert doc.count("\n- ") + doc.count("- ") >= 7


@pytest.mark.parametrize(
    "removed",
    [
        "user_local_list",
        "user_group_list",
        "user_radius_list",
        "user_ldap_list",
        "user_tacacs_list",
        "user_saml_list",
        "monitor_user_fortitoken_list",
        "user_local_get",
        "user_group_get",
        "user_radius_get",
    ],
)
async def test_the_replaced_user_tools_are_gone(removed: str) -> None:
    from server import mcp

    names = {tool.name for tool in await mcp.list_tools()}
    assert removed not in names, f"{removed} should have folded into user_read"


async def test_user_read_is_registered_and_read_only() -> None:
    from server import mcp

    tools = {tool.name: tool for tool in await mcp.list_tools()}
    assert "user_read" in tools
    tool = tools["user_read"]
    assert tool.annotations is not None
    assert tool.annotations.readOnlyHint is True
    props = tool.inputSchema["properties"]
    assert set(props) == {"resource", "name", "instance", "vdom"}
    assert props["resource"]["enum"] == sorted(props["resource"]["enum"])
    assert len(props["resource"]["enum"]) == 7
