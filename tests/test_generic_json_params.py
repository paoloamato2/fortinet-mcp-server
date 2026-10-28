"""Tests for JSON-object-or-string parameters in tools/generic.py."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from server import mcp
from tools.generic import _as_dict


def test_as_dict_none_and_empty_string():
    assert _as_dict(None, "extra_params") is None
    assert _as_dict("", "extra_params") is None


def test_as_dict_dict_passthrough():
    value = {"a": 1}
    assert _as_dict(value, "extra_params") is value


def test_as_dict_valid_json_string():
    assert _as_dict('{"a": 1}', "extra_params") == {"a": 1}


def test_as_dict_invalid_json_raises():
    with pytest.raises(ValueError, match="Invalid JSON in extra_params"):
        _as_dict("{not json", "extra_params")


def test_as_dict_non_object_json_raises():
    with pytest.raises(ValueError, match="extra_params must be a JSON object"):
        _as_dict("[1,2]", "extra_params")


def _ctx(client):
    return SimpleNamespace(
        request_context=SimpleNamespace(lifespan_context={"client": client})
    )


async def _monitor_get(client, extra_params):
    fn = mcp._tool_manager.get_tool("monitor_get").fn
    return await fn(
        _ctx(client), monitor_path="system/status", extra_params=extra_params
    )


@pytest.mark.asyncio
async def test_monitor_get_dict_and_string_forward_same_params():
    dict_client = AsyncMock()
    str_client = AsyncMock()
    await _monitor_get(dict_client, {"tunnel_name": "vpn1"})
    await _monitor_get(str_client, '{"tunnel_name": "vpn1"}')
    assert dict_client.monitor_get.call_args.args[1] == {"tunnel_name": "vpn1"}
    assert (
        str_client.monitor_get.call_args.args[1]
        == dict_client.monitor_get.call_args.args[1]
    )


@pytest.mark.asyncio
async def test_monitor_get_invalid_string_returns_error_dict():
    client = AsyncMock()
    result = await _monitor_get(client, "{oops")
    assert result["error"].startswith("Invalid JSON in extra_params")
    client.monitor_get.assert_not_called()
