"""End-to-end tests that tool calls reach the instance they name."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from mcp.shared.memory import create_connected_server_and_client_session
from pytest_httpx import HTTPXMock


@pytest.fixture
def fleet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "fortigates.json"
    path.write_text(
        json.dumps(
            [
                {
                    "name": "hq-fw",
                    "description": "HQ perimeter",
                    "host": "https://hq.example",
                    "api_token": "t",
                    "read_only": True,
                },
                {
                    "name": "dc-edge",
                    "description": "DC edge",
                    "host": "https://dc.example",
                    "api_token": "t",
                },
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


async def test_named_instance_is_the_only_one_contacted(
    fleet: None, httpx_mock: HTTPXMock
) -> None:
    httpx_mock.add_response(
        url="https://dc.example/api/v2/cmdb/firewall/policy?vdom=root",
        json={"results": [{"policyid": 2}], "http_status": 200},
    )

    payload = await _call(
        "cmdb_list", {"resource_path": "firewall/policy", "instance": "dc-edge"}
    )

    assert payload["results"][0]["policyid"] == 2
    requests = httpx_mock.get_requests()
    assert len(requests) == 1
    assert requests[0].url.host == "dc.example"


async def test_omitting_instance_with_two_configured_returns_an_error(
    fleet: None, httpx_mock: HTTPXMock
) -> None:
    payload = await _call("cmdb_list", {"resource_path": "firewall/policy"})

    assert "'instance' is required" in payload["error"]
    assert "hq-fw, dc-edge" in payload["error"]
    assert httpx_mock.get_requests() == []


async def test_unknown_instance_returns_an_error(
    fleet: None, httpx_mock: HTTPXMock
) -> None:
    payload = await _call(
        "cmdb_list", {"resource_path": "firewall/policy", "instance": "nope"}
    )

    assert "Unknown instance 'nope'" in payload["error"]
    assert httpx_mock.get_requests() == []


async def test_star_fans_out_and_keys_results_by_instance(
    fleet: None, httpx_mock: HTTPXMock
) -> None:
    httpx_mock.add_response(
        url="https://hq.example/api/v2/cmdb/firewall/policy?vdom=root",
        json={"results": [{"policyid": 1}], "http_status": 200},
    )
    httpx_mock.add_response(
        url="https://dc.example/api/v2/cmdb/firewall/policy?vdom=root",
        json={"results": [{"policyid": 2}], "http_status": 200},
    )

    payload = await _call(
        "cmdb_list", {"resource_path": "firewall/policy", "instance": "*"}
    )

    assert payload["hq-fw"]["results"][0]["policyid"] == 1
    assert payload["dc-edge"]["results"][0]["policyid"] == 2


async def test_write_to_a_read_only_instance_is_refused(
    fleet: None, httpx_mock: HTTPXMock
) -> None:
    payload = await _call(
        "cmdb_delete",
        {"resource_path": "firewall/policy/1", "instance": "hq-fw"},
    )

    assert "read-only" in payload["error"]
    assert payload["status_code"] == 403
    assert httpx_mock.get_requests() == []


async def test_write_with_star_is_refused(fleet: None, httpx_mock: HTTPXMock) -> None:
    payload = await _call(
        "cmdb_delete", {"resource_path": "firewall/policy/1", "instance": "*"}
    )

    assert "read-only" in payload["error"]
    assert httpx_mock.get_requests() == []


async def test_single_instance_config_allows_omitting_instance(
    monkeypatch: pytest.MonkeyPatch, httpx_mock: HTTPXMock
) -> None:
    monkeypatch.setenv("FORTIOS_HOST", "https://only.example")
    monkeypatch.setenv("FORTIOS_API_TOKEN", "t")
    httpx_mock.add_response(
        url="https://only.example/api/v2/cmdb/firewall/policy?vdom=root",
        json={"results": [], "http_status": 200},
    )

    payload = await _call("cmdb_list", {"resource_path": "firewall/policy"})

    assert payload["results"] == []


async def test_typed_firewall_tool_also_honours_instance(
    fleet: None, httpx_mock: HTTPXMock
) -> None:
    httpx_mock.add_response(
        url="https://dc.example/api/v2/cmdb/firewall/policy?vdom=root&start=0&count=200",
        json={"results": [{"policyid": 9}], "http_status": 200},
    )

    payload = await _call("firewall_policy_list", {"instance": "dc-edge"})

    assert payload["results"][0]["policyid"] == 9
    assert httpx_mock.get_requests()[0].url.host == "dc.example"


async def test_typed_firewall_tool_reports_ambiguous_omission(
    fleet: None, httpx_mock: HTTPXMock
) -> None:
    payload = await _call("firewall_policy_list", {})

    assert "'instance' is required" in payload["error"]
    assert httpx_mock.get_requests() == []
