"""Tests for ``vdom="*"`` responses, which FortiOS returns as a JSON array.

Every other call returns a single JSON object. Asking for all VDOMs instead
returns one envelope per VDOM in a list, which the response parser used to hand
straight to ``dict.get`` -- raising ``AttributeError`` rather than
``FortiOSError``, so the tools' ``except FortiOSError`` handlers missed it and
it escaped to the MCP layer. Confirmed against FortiOS 7.6.6 on 2026-07-28.

The list is collapsed into ``{vdom_name: envelope}``, matching the shape
``FanOutClient`` already returns for ``instance="*"``: one fan-out concept, one
response shape.
"""

from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from fortios_client import FortiOSClient, FortiOSError


def _client() -> FortiOSClient:
    return FortiOSClient(host="https://fw.example", api_token="tok", name="hq-fw")


def _envelope(vdom: str, **extra: object) -> dict[str, object]:
    return {
        "http_method": "GET",
        "vdom": vdom,
        "path": "firewall",
        "name": "policy",
        "status": "success",
        "http_status": 200,
        "results": [{"policyid": 1}],
        **extra,
    }


async def test_vdom_star_returns_one_entry_per_vdom(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url="https://fw.example/api/v2/cmdb/firewall/policy?vdom=*",
        json=[_envelope("root"), _envelope("guest")],
    )
    async with _client() as client:
        result = await client.cmdb_get("firewall/policy", vdom="*")

    assert sorted(result) == ["guest", "root"]
    assert result["root"]["results"] == [{"policyid": 1}]
    assert result["guest"]["vdom"] == "guest"


async def test_monitor_get_handles_the_array_too(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url="https://fw.example/api/v2/monitor/system/status?vdom=*",
        json=[_envelope("root")],
    )
    async with _client() as client:
        result = await client.monitor_get("system/status", vdom="*")

    assert list(result) == ["root"]


async def test_one_failing_vdom_does_not_sink_the_others(
    httpx_mock: HTTPXMock,
) -> None:
    """A per-VDOM failure is reported in that VDOM's slot, like instance fan-out."""
    httpx_mock.add_response(
        url="https://fw.example/api/v2/cmdb/firewall/policy?vdom=*",
        json=[
            _envelope("root"),
            _envelope("guest", status="error", http_status=403, results=None),
        ],
    )
    async with _client() as client:
        result = await client.cmdb_get("firewall/policy", vdom="*")

    assert result["root"]["results"] == [{"policyid": 1}]
    assert result["guest"]["status_code"] == 403
    assert "403" in result["guest"]["error"]


async def test_an_envelope_without_a_vdom_field_still_gets_a_slot(
    httpx_mock: HTTPXMock,
) -> None:
    """Never drop an envelope just because FortiOS omitted the vdom name."""
    payload = _envelope("root")
    del payload["vdom"]
    httpx_mock.add_response(
        url="https://fw.example/api/v2/cmdb/firewall/policy?vdom=*",
        json=[payload],
    )
    async with _client() as client:
        result = await client.cmdb_get("firewall/policy", vdom="*")

    assert len(result) == 1
    assert next(iter(result.values()))["results"] == [{"policyid": 1}]


async def test_single_vdom_responses_are_untouched(httpx_mock: HTTPXMock) -> None:
    """The ordinary dict path must not change shape."""
    httpx_mock.add_response(
        url="https://fw.example/api/v2/cmdb/firewall/policy?vdom=root",
        json=_envelope("root"),
    )
    async with _client() as client:
        result = await client.cmdb_get("firewall/policy")

    assert result["results"] == [{"policyid": 1}]
    assert "root" not in result


async def test_an_http_error_on_the_whole_request_still_raises(
    httpx_mock: HTTPXMock,
) -> None:
    """A transport-level failure is not a per-VDOM failure and must still raise."""
    httpx_mock.add_response(
        url="https://fw.example/api/v2/cmdb/firewall/policy?vdom=*",
        status_code=401,
        json={"http_status": 401, "status": "error"},
    )
    async with _client() as client:
        with pytest.raises(FortiOSError) as excinfo:
            await client.cmdb_get("firewall/policy", vdom="*")

    assert excinfo.value.status_code == 401
