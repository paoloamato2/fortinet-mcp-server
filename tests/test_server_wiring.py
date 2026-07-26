"""Tests for server lifespan wiring and the instructions roster."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import server
from instances import InstanceRegistry


def _write_fleet(tmp_path: Path) -> str:
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
    return str(path)


async def test_lifespan_yields_a_registry_with_every_instance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", _write_fleet(tmp_path))

    async with server.lifespan(server.mcp) as ctx:
        registry = ctx["registry"]
        assert isinstance(registry, InstanceRegistry)
        assert registry.names() == ["hq-fw", "dc-edge"]
        assert registry.clients["hq-fw"].read_only is True


async def test_lifespan_raises_on_invalid_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "fortigates.json"
    path.write_text(json.dumps([{"name": "a"}]), encoding="utf-8")
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", str(path))

    with pytest.raises(EnvironmentError) as excinfo:
        async with server.lifespan(server.mcp):
            pass

    assert "invalid" in str(excinfo.value)


async def test_lifespan_raises_when_nothing_is_configured() -> None:
    with pytest.raises(EnvironmentError) as excinfo:
        async with server.lifespan(server.mcp):
            pass

    assert "No FortiGate" in str(excinfo.value)


def test_importing_server_without_env_still_works() -> None:
    # Guards the contract that tests/test_server.py relies on.
    assert server.mcp.name == "FortiOS MCP Server"


def test_instructions_mention_the_instance_parameter() -> None:
    instructions = server.mcp.instructions or ""

    assert "instance" in instructions
