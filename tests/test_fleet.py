"""Tests for the fortigate_list meta tool."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from mcp.shared.memory import create_connected_server_and_client_session
from pytest_httpx import HTTPXMock


def _write_fleet(tmp_path: Path) -> str:
    path = tmp_path / "fortigates.json"
    path.write_text(
        json.dumps(
            [
                {
                    "name": "hq-fw",
                    "description": "HQ perimeter",
                    "host": "https://hq.example",
                    "api_token": "super-secret-token",
                    "read_only": True,
                },
                {
                    "name": "dc-edge",
                    "description": "DC edge",
                    "host": "https://dc.example",
                    "api_token": "another-secret",
                    "vdom": "tenant1",
                },
            ]
        ),
        encoding="utf-8",
    )
    return str(path)


async def _call(tool: str, args: dict[str, object]) -> str:
    from server import mcp

    async with create_connected_server_and_client_session(mcp) as client:
        result = await client.call_tool(tool, args)
    assert not result.isError, result.content
    return result.content[0].text  # type: ignore[union-attr]


async def test_lists_instances_with_descriptions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", _write_fleet(tmp_path))

    payload = json.loads(await _call("fortigate_list", {}))

    assert [i["name"] for i in payload["instances"]] == ["hq-fw", "dc-edge"]
    assert payload["instances"][0]["description"] == "HQ perimeter"
    assert payload["instances"][0]["read_only"] is True
    assert payload["instances"][1]["vdom"] == "tenant1"
    assert payload["count"] == 2


async def test_never_leaks_api_tokens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", _write_fleet(tmp_path))

    raw = await _call("fortigate_list", {})

    assert "super-secret-token" not in raw
    assert "another-secret" not in raw


async def test_health_check_reports_reachable_and_unreachable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, httpx_mock: HTTPXMock
) -> None:
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", _write_fleet(tmp_path))
    # Real FortiOS 7.6.x envelope: version/serial/build are top-level keys,
    # results only carries hostname/model details.
    httpx_mock.add_response(
        url="https://hq.example/api/v2/monitor/system/status?vdom=root",
        json={
            "http_method": "GET",
            "results": {"model_name": "FortiGate", "hostname": "fw-1"},
            "status": "success",
            "serial": "FG-1",
            "version": "v7.6.6",
            "build": 3652,
            "http_status": 200,
        },
    )
    httpx_mock.add_response(
        url="https://dc.example/api/v2/monitor/system/status?vdom=tenant1",
        status_code=401,
        json={"http_status": 401, "status": "error", "cli_error": "bad token"},
    )

    payload = json.loads(await _call("fortigate_list", {"check_health": True}))
    by_name = {i["name"]: i for i in payload["instances"]}

    assert by_name["hq-fw"]["reachable"] is True
    assert by_name["hq-fw"]["version"] == "v7.6.6"
    assert by_name["hq-fw"]["serial"] == "FG-1"
    assert by_name["dc-edge"]["reachable"] is False
    assert "error" in by_name["dc-edge"]


async def test_health_check_is_not_run_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, httpx_mock: HTTPXMock
) -> None:
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", _write_fleet(tmp_path))

    payload = json.loads(await _call("fortigate_list", {}))

    assert "reachable" not in payload["instances"][0]
    assert httpx_mock.get_requests() == []
