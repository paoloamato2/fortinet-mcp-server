"""The typed readers that return unbounded lists are paged too.

Measured on FortiOS 7.6.6: firewall_address_list 296,597 characters over 374
rows, system_interface_list 630,143 over 77. The interface rows average 8,183
characters each, which is why the character budget and not just the row count
has to apply here.

Drives the real tools through an in-memory MCP session, the pattern
``tests/test_generic_format_fields.py`` established, so what is asserted is
the request the tool actually issues rather than a hand-built client call.

The rosters below are named rather than discovered because each tool needs a
different argument to exercise its filter. That makes them liable to lag
behind a newly added tool, so ``test_every_list_tool_is_covered_by_a_roster``
below reconciles them against the discovered set in
``tests/test_list_tools_are_paged.py``; the structural contract itself is that
file's job.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from mcp.shared.memory import create_connected_server_and_client_session
from pytest_httpx import HTTPXMock

from paging import PAGE_ROWS
from tests.test_list_tools_are_paged import _list_tools

#: CMDB readers, which report a total and take a ``filter`` expression.
#: (tool name, the extra argument it takes, the filter that argument produces)
READERS = [
    ("firewall_address_list", {"filter_type": "fqdn"}, "type==fqdn"),
    ("system_interface_list", {"include_vlan": False}, "type!=vlan"),
    ("firewall_policy_list", {"filter_srcintf": "port1"}, "srcintf==port1"),
]

#: Monitor readers. Same paging contract, but the monitor family reports no
#: ``size``, so ``_page.total`` is ``None`` and their filters are ordinary
#: query parameters rather than a ``filter`` expression.
MONITOR_READERS = [
    "monitor_firewall_session_list",
    "monitor_endpoint_record_list",
    "monitor_wifi_client_list",
]

PAGED_TOOLS = [name for name, _, _ in READERS] + MONITOR_READERS

#: Paged, but driven from another module: ``cmdb_list`` is the generic
#: pass-through and takes an arbitrary ``resource_path``, so its paging is
#: exercised in ``tests/test_generic_paging.py`` rather than against a fixed
#: endpoint here.
COVERED_ELSEWHERE = {"cmdb_list"}


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


@pytest.mark.parametrize("tool", PAGED_TOOLS)
async def test_a_default_call_asks_for_one_extra_row(
    single_fw: None, httpx_mock: HTTPXMock, tool: str
) -> None:
    httpx_mock.add_response(json={"results": [], "http_status": 200})

    await _call(tool, {"instance": "hq-fw"})

    request = httpx_mock.get_requests()[0]
    assert request.url.params["start"] == "0"
    assert request.url.params["count"] == str(PAGE_ROWS + 1)


@pytest.mark.parametrize("tool", PAGED_TOOLS)
async def test_explicit_start_and_count_are_forwarded(
    single_fw: None, httpx_mock: HTTPXMock, tool: str
) -> None:
    httpx_mock.add_response(json={"results": [], "http_status": 200})

    await _call(tool, {"instance": "hq-fw", "start": 100, "count": 5})

    request = httpx_mock.get_requests()[0]
    assert request.url.params["start"] == "100"
    assert request.url.params["count"] == "6"


@pytest.mark.parametrize(("tool", "extra", "expected_filter"), READERS)
async def test_the_existing_filter_survives_alongside_paging(
    single_fw: None,
    httpx_mock: HTTPXMock,
    tool: str,
    extra: dict[str, object],
    expected_filter: str,
) -> None:
    """Paging must not displace the filter each reader was kept for."""
    httpx_mock.add_response(json={"results": [], "http_status": 200})

    await _call(tool, {"instance": "hq-fw", **extra})

    request = httpx_mock.get_requests()[0]
    assert request.url.params["filter"] == expected_filter
    assert request.url.params["count"] == str(PAGE_ROWS + 1)


@pytest.mark.parametrize("tool", [name for name, _, _ in READERS])
async def test_page_info_is_attached_with_the_cmdb_total(
    single_fw: None, httpx_mock: HTTPXMock, tool: str
) -> None:
    httpx_mock.add_response(
        json={"results": [{"name": "a"}], "http_status": 200, "size": 374}
    )

    payload = await _call(tool, {"instance": "hq-fw"})

    assert payload["_page"] == {
        "start": 0,
        "returned": 1,
        "more": False,
        "next_start": None,
        "total": 374,
    }


@pytest.mark.parametrize("tool", PAGED_TOOLS)
@pytest.mark.parametrize(
    ("args", "reason"), [({"count": 0}, "count"), ({"start": -1}, "start")]
)
async def test_an_impossible_page_is_refused_without_calling_the_device(
    single_fw: None,
    httpx_mock: HTTPXMock,
    tool: str,
    args: dict[str, object],
    reason: str,
) -> None:
    """The guard has to fire here, not at the FortiGate.

    ``firewall_policy_list`` used to forward both of these verbatim, and the
    device answering with an empty list read as the guard working.
    """
    payload = await _call(tool, {"instance": "hq-fw", **args})

    assert reason in payload["error"]
    assert httpx_mock.get_requests() == []


@pytest.mark.parametrize("tool", MONITOR_READERS)
async def test_a_monitor_list_pages_without_a_reported_total(
    single_fw: None, httpx_mock: HTTPXMock, tool: str
) -> None:
    """The monitor family reports no ``size``, so ``total`` stays ``None``."""
    httpx_mock.add_response(
        json={"results": [{"id": 1}, {"id": 2}], "http_status": 200}
    )

    payload = await _call(tool, {"instance": "hq-fw", "count": 1})

    assert payload["_page"] == {
        "start": 0,
        "returned": 1,
        "more": True,
        "next_start": 1,
        "total": None,
    }
    assert payload["results"] == [{"id": 1}]


def test_every_list_tool_is_covered_by_a_roster() -> None:
    """A newly added list tool must join a roster, not slip past unexercised."""
    discovered = {fn.name for _, fn in _list_tools()} - COVERED_ELSEWHERE

    assert discovered == set(PAGED_TOOLS), (
        "rosters and discovered list tools disagree; "
        f"missing from rosters: {sorted(discovered - set(PAGED_TOOLS))}, "
        f"stale roster entries: {sorted(set(PAGED_TOOLS) - discovered)}"
    )
