"""Tests that cmdb_list translates format_fields into the FortiOS format param.

FortiOS expects pipe-separated field names in the ``format`` query parameter
and silently returns empty objects for every result when it gets commas, so
the translation is load-bearing: without it the tool reports success while
returning no data.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from mcp.shared.memory import create_connected_server_and_client_session
from pytest_httpx import HTTPXMock


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


async def test_comma_separated_format_fields_sent_pipe_separated(
    single_fw: None, httpx_mock: HTTPXMock
) -> None:
    httpx_mock.add_response(json={"results": [], "http_status": 200})

    await _call(
        "cmdb_list",
        {"resource_path": "firewall/address", "format_fields": "name, subnet,type"},
    )

    request = httpx_mock.get_requests()[0]
    assert request.url.params["format"] == "name|subnet|type"


async def test_pipe_separated_format_fields_pass_through(
    single_fw: None, httpx_mock: HTTPXMock
) -> None:
    httpx_mock.add_response(json={"results": [], "http_status": 200})

    await _call(
        "cmdb_list",
        {"resource_path": "firewall/address", "format_fields": "name|subnet"},
    )

    request = httpx_mock.get_requests()[0]
    assert request.url.params["format"] == "name|subnet"
