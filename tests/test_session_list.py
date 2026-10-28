"""Tests for monitor_firewall_session_list paging and client-side filtering."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from fortios_client import FortiOSError
from server import mcp

SESSIONS = [
    {
        "saddr": "10.0.0.1",
        "daddr": "8.8.8.8",
        "sport": 1000,
        "dport": 53,
        "proto": "udp",
    },
    {
        "saddr": "10.0.0.2",
        "daddr": "1.1.1.1",
        "sport": 2000,
        "dport": 443,
        "proto": "tcp",
    },
    {
        "saddr": "10.0.0.1",
        "daddr": "1.1.1.1",
        "sport": 3000,
        "dport": 443,
        "proto": "tcp",
    },
]


def _response(details):
    return {"results": {"details": details, "summary": {"matched_count": 3}}}


def _ctx(client):
    return SimpleNamespace(
        request_context=SimpleNamespace(lifespan_context={"client": client})
    )


def _client(response=None, error=None):
    client = AsyncMock()
    if error is not None:
        client.monitor_get.side_effect = error
    else:
        client.monitor_get.return_value = response
    return client


async def _call(client, **kwargs):
    fn = mcp._tool_manager.get_tool("monitor_firewall_session_list").fn
    return await fn(_ctx(client), **kwargs)


def _sent_params(client):
    return client.monitor_get.call_args.args[1]


@pytest.mark.asyncio
async def test_params_contain_count_and_start():
    client = _client(_response(list(SESSIONS)))
    await _call(client, count=50, start=100)
    assert _sent_params(client) == {"count": 50, "start": 100}


@pytest.mark.asyncio
async def test_summary_flag_adds_summary_true():
    client = _client(_response(list(SESSIONS)))
    await _call(client, summary=True)
    params = _sent_params(client)
    assert params["summary"] == "true"
    assert params["start"] == 0


@pytest.mark.asyncio
async def test_filter_by_srcaddr_client_side():
    client = _client(_response(list(SESSIONS)))
    result = await _call(client, srcaddr="10.0.0.1")
    assert [s["sport"] for s in result["results"]["details"]] == [1000, 3000]


@pytest.mark.asyncio
async def test_filter_by_protocol_udp():
    client = _client(_response(list(SESSIONS)))
    result = await _call(client, protocol=17)
    assert [s["proto"] for s in result["results"]["details"]] == ["udp"]


@pytest.mark.asyncio
async def test_filter_by_dstport():
    client = _client(_response(list(SESSIONS)))
    result = await _call(client, dstport=443)
    assert len(result["results"]["details"]) == 2


@pytest.mark.asyncio
async def test_no_filters_leaves_details_unchanged():
    client = _client(_response(list(SESSIONS)))
    result = await _call(client)
    assert result["results"]["details"] == SESSIONS


@pytest.mark.asyncio
async def test_missing_details_returns_result_unchanged():
    payload = {"results": {"summary": {"matched_count": 0}}}
    client = _client(payload)
    result = await _call(client, srcaddr="10.0.0.1")
    assert result == {"results": {"summary": {"matched_count": 0}}}


@pytest.mark.asyncio
async def test_fortios_error_returns_error_dict():
    client = _client(error=FortiOSError("boom", status_code=500))
    result = await _call(client)
    assert result == {"error": "boom", "status_code": 500}
