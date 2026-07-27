"""Tests for server lifespan wiring and the instructions roster."""

from __future__ import annotations

import importlib
import json
import re
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


def test_instructions_do_not_assert_an_unchecked_firmware_version() -> None:
    """The instructions are shown to the LLM as fact, and nothing in this
    server enforces or detects the firmware a device runs — a fleet can be
    mixed. Asserting a concrete version there ("running FortiOS 7.6.6") tells
    the model something that may be false, so no full version literal may
    appear; the guidance points at system_status instead.
    """
    instructions = server.mcp.instructions or ""

    assert not re.search(r"\d+\.\d+\.\d+", instructions), instructions
    assert "system_status" in instructions


def test_reloading_under_a_populated_fleet_renders_the_roster(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`server._IMPORT_INSTANCES` is evaluated once, at import time — which,
    for the test suite, happens at collection, before conftest's autouse env
    scrub ever runs. The only prior assertion on the instructions block,
    `"instance" in instructions`, passes even for the *empty*-fleet roster,
    because `roster_text([])` itself contains the word "instances". Nothing
    proved a populated, multi-device roster actually renders.

    This test forces a re-import of `server` under a two-instance fleet (via
    `importlib.reload`, since `import server` alone would hit the module
    cache) and asserts the real rendered text: both instance names, and the
    "`instance` is required" sentence that only appears once there is more
    than one configured FortiGate.
    """
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", _write_fleet(tmp_path))
    try:
        importlib.reload(server)
        instructions = server.mcp.instructions or ""

        assert "hq-fw" in instructions
        assert "dc-edge" in instructions
        assert "`instance` is required" in instructions
    finally:
        # Restore module state so the reloaded, populated-fleet `mcp` object
        # does not leak into other tests: clear the env this test set, then
        # reload again so `server.mcp` goes back to reflecting an empty
        # fleet, matching how every other test in this suite expects to find
        # it.
        monkeypatch.delenv("FORTIOS_INSTANCES_FILE", raising=False)
        importlib.reload(server)
