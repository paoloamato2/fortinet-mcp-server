"""``cmdb_list`` and ``monitor_get`` -- the two generic pass-throughs -- are paged.

Before this, ``cmdb_list("firewall/address")`` returned all 296,597 characters
and ``monitor_get("wifi/rogue_ap")`` returned 1,274,739 -- unbounded, because
``cmdb_list`` accepted ``start``/``count`` but only forwarded them when not
``None``, and ``monitor_get`` had no paging support at all. ``server.py``'s
MCP instructions point the model at these two tools for any endpoint outside
the read table, so leaving them unbounded left exactly the failure mode this
feature exists to stop.

Drives the real tools through an in-memory MCP session, the pattern
``tests/test_generic_format_fields.py`` and ``tests/test_typed_reader_paging.py``
established, so what is asserted is the request the tool actually issues.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from mcp.shared.memory import create_connected_server_and_client_session
from pytest_httpx import HTTPXMock

from paging import PAGE_ROWS


@pytest.fixture
def single_fw(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "fortigates.json"
    path.write_text(
        json.dumps(
            [
                {
                    "name": "hq-fw",
                    "description": "HQ perimeter",
                    "host": "https://hq.example",
                    "api_token": "t",
                }
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", str(path))


async def _call(tool: str, args: dict[str, object]) -> dict[str, Any]:
    from server import mcp

    async with create_connected_server_and_client_session(mcp) as client:
        result = await client.call_tool(tool, args)
    assert not result.isError, result.content
    return json.loads(result.content[0].text)  # type: ignore[union-attr]


# --------------------------------------------------------------- cmdb_list


async def test_cmdb_list_default_call_asks_for_one_extra_row(
    single_fw: None, httpx_mock: HTTPXMock
) -> None:
    httpx_mock.add_response(json={"results": [], "http_status": 200})

    await _call("cmdb_list", {"resource_path": "firewall/address", "instance": "hq-fw"})

    request = httpx_mock.get_requests()[0]
    assert request.url.params["start"] == "0"
    assert request.url.params["count"] == str(PAGE_ROWS + 1)


async def test_cmdb_list_explicit_start_and_count_are_forwarded(
    single_fw: None, httpx_mock: HTTPXMock
) -> None:
    httpx_mock.add_response(json={"results": [], "http_status": 200})

    await _call(
        "cmdb_list",
        {
            "resource_path": "firewall/address",
            "instance": "hq-fw",
            "start": 100,
            "count": 5,
        },
    )

    request = httpx_mock.get_requests()[0]
    assert request.url.params["start"] == "100"
    assert request.url.params["count"] == "6"


async def test_cmdb_list_filter_and_format_survive_alongside_paging(
    single_fw: None, httpx_mock: HTTPXMock
) -> None:
    """Paging must not displace the filter/format params cmdb_list was kept for."""
    httpx_mock.add_response(json={"results": [], "http_status": 200})

    await _call(
        "cmdb_list",
        {
            "resource_path": "firewall/address",
            "instance": "hq-fw",
            "filters": "status==enable",
            "format_fields": "name, subnet",
        },
    )

    request = httpx_mock.get_requests()[0]
    assert request.url.params["filter"] == "status==enable"
    assert request.url.params["format"] == "name|subnet"
    assert request.url.params["count"] == str(PAGE_ROWS + 1)


async def test_cmdb_list_page_info_is_attached(
    single_fw: None, httpx_mock: HTTPXMock
) -> None:
    httpx_mock.add_response(
        json={"results": [{"name": "a"}], "http_status": 200, "size": 296597}
    )

    payload = await _call(
        "cmdb_list", {"resource_path": "firewall/address", "instance": "hq-fw"}
    )

    assert payload["_page"] == {
        "start": 0,
        "returned": 1,
        "more": False,
        "next_start": None,
        "total": 296597,
    }


async def test_cmdb_list_impossible_page_is_refused_without_calling_the_device(
    single_fw: None, httpx_mock: HTTPXMock
) -> None:
    payload = await _call(
        "cmdb_list",
        {"resource_path": "firewall/address", "instance": "hq-fw", "count": 0},
    )

    assert "error" in payload
    assert "status_code" not in payload
    assert httpx_mock.get_requests() == []


# -------------------------------------------------------------- monitor_get


async def test_monitor_get_default_call_asks_for_one_extra_row(
    single_fw: None, httpx_mock: HTTPXMock
) -> None:
    httpx_mock.add_response(json={"results": [], "http_status": 200})

    await _call("monitor_get", {"monitor_path": "wifi/rogue_ap", "instance": "hq-fw"})

    request = httpx_mock.get_requests()[0]
    assert request.url.params["start"] == "0"
    assert request.url.params["count"] == str(PAGE_ROWS + 1)


async def test_monitor_get_explicit_start_and_count_are_forwarded(
    single_fw: None, httpx_mock: HTTPXMock
) -> None:
    httpx_mock.add_response(json={"results": [], "http_status": 200})

    await _call(
        "monitor_get",
        {
            "monitor_path": "wifi/rogue_ap",
            "instance": "hq-fw",
            "start": 10,
            "count": 2,
        },
    )

    request = httpx_mock.get_requests()[0]
    assert request.url.params["start"] == "10"
    assert request.url.params["count"] == "3"


class _FakeMonitorClient:
    """Records the ``monitor_get`` call instead of reaching a FortiGate.

    ``monitor_get``'s ``extra_params`` is a JSON-*string* parameter. FastMCP's
    ``pre_parse_json`` pre-parses any string argument whose field annotation
    is not the bare ``str`` type (``str | None`` qualifies) -- so a caller
    who genuinely sends a JSON-*object*-shaped string for ``extra_params``
    through a real MCP session has that string silently replaced with a
    dict, which then fails the tool's own ``str | None`` schema before the
    call ever reaches this module. That is a pre-existing framework/typing
    interaction on every optional JSON-string parameter in this codebase
    (``body``, ``extra_params`` elsewhere too), orthogonal to paging, so
    these precedence tests call the registered tool's underlying function
    directly -- bypassing FastMCP's argument model entirely -- the same way
    ``tests/test_read_tools.py`` drives ``read_resource`` directly.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any] | None, str | None]] = []

    async def monitor_get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        self.calls.append(("monitor_get", path, params, vdom))
        return {"results": [], "path": path}


class _FakeToolContext:
    def __init__(self, client: _FakeMonitorClient) -> None:
        class _Registry:
            def resolve(self, _instance: str | None) -> _FakeMonitorClient:
                return client

        class _RequestContext:
            lifespan_context = {"registry": _Registry()}

        self.request_context = _RequestContext()

    async def error(self, _message: str) -> None:
        return None


def _monitor_get_fn() -> Any:
    from server import mcp

    tool = mcp._tool_manager.get_tool("monitor_get")
    assert tool is not None, "monitor_get must be registered"
    return tool.fn


async def test_monitor_get_extra_params_survive_alongside_paging() -> None:
    client = _FakeMonitorClient()
    await _monitor_get_fn()(
        _FakeToolContext(client),
        monitor_path="vpn/ipsec",
        extra_params=json.dumps({"tunnel_name": "my-vpn"}),
    )
    assert client.calls == [
        (
            "monitor_get",
            "vpn/ipsec",
            {"tunnel_name": "my-vpn", "start": 0, "count": PAGE_ROWS + 1},
            None,
        )
    ]


async def test_monitor_get_honours_extra_params_count_when_no_explicit_count() -> None:
    """A caller who wrote extra_params='{"count": 5}' must get 5 rows, not 50."""
    client = _FakeMonitorClient()
    await _monitor_get_fn()(
        _FakeToolContext(client),
        monitor_path="wifi/rogue_ap",
        extra_params=json.dumps({"count": 5}),
    )
    assert client.calls == [
        ("monitor_get", "wifi/rogue_ap", {"start": 0, "count": 6}, None)
    ]


async def test_monitor_get_explicit_count_wins_over_extra_params() -> None:
    """An explicit `count` parameter wins over a count inside extra_params."""
    client = _FakeMonitorClient()
    await _monitor_get_fn()(
        _FakeToolContext(client),
        monitor_path="wifi/rogue_ap",
        extra_params=json.dumps({"count": 5}),
        count=3,
    )
    assert client.calls == [
        ("monitor_get", "wifi/rogue_ap", {"start": 0, "count": 4}, None)
    ]


async def test_monitor_get_extra_params_start_used_when_no_explicit_start() -> None:
    client = _FakeMonitorClient()
    await _monitor_get_fn()(
        _FakeToolContext(client),
        monitor_path="wifi/rogue_ap",
        extra_params=json.dumps({"start": 20}),
    )
    assert client.calls == [
        ("monitor_get", "wifi/rogue_ap", {"start": 20, "count": PAGE_ROWS + 1}, None)
    ]


async def test_monitor_get_explicit_start_wins_over_extra_params() -> None:
    client = _FakeMonitorClient()
    await _monitor_get_fn()(
        _FakeToolContext(client),
        monitor_path="wifi/rogue_ap",
        extra_params=json.dumps({"start": 20}),
        start=5,
    )
    assert client.calls == [
        ("monitor_get", "wifi/rogue_ap", {"start": 5, "count": PAGE_ROWS + 1}, None)
    ]


async def test_monitor_get_page_info_is_attached_with_null_total(
    single_fw: None, httpx_mock: HTTPXMock
) -> None:
    httpx_mock.add_response(json={"results": [{"mac": "aa"}], "http_status": 200})

    payload = await _call(
        "monitor_get", {"monitor_path": "wifi/rogue_ap", "instance": "hq-fw"}
    )

    assert payload["_page"] == {
        "start": 0,
        "returned": 1,
        "more": False,
        "next_start": None,
        "total": None,
    }


async def test_monitor_get_impossible_page_is_refused_without_calling_the_device(
    single_fw: None, httpx_mock: HTTPXMock
) -> None:
    payload = await _call(
        "monitor_get",
        {"monitor_path": "wifi/rogue_ap", "instance": "hq-fw", "count": 0},
    )

    assert "error" in payload
    assert "status_code" not in payload
    assert httpx_mock.get_requests() == []
