"""Tests for instance resolution."""

from __future__ import annotations

import pytest

from fortios_client import FortiOSClient, FortiOSError
from instances import ErrorClient, InstanceConfig, InstanceRegistry, roster_text


def _cfg(name: str, read_only: bool = False) -> InstanceConfig:
    return InstanceConfig(
        name=name,
        description=f"{name} description",
        host=f"https://{name}.example",
        api_token="tok",
        read_only=read_only,
    )


def test_single_instance_resolves_when_omitted() -> None:
    registry = InstanceRegistry([_cfg("only-fw")])

    client = registry.resolve(None)

    assert isinstance(client, FortiOSClient)
    assert client.name == "only-fw"


@pytest.mark.parametrize("omitted", [None, "", "   "])
async def test_omitting_instance_with_several_configured_errors(
    omitted: str | None,
) -> None:
    registry = InstanceRegistry([_cfg("a"), _cfg("b"), _cfg("c")])

    client = registry.resolve(omitted)

    assert isinstance(client, ErrorClient)
    with pytest.raises(FortiOSError) as excinfo:
        await client.cmdb_get("firewall/policy")
    message = str(excinfo.value)
    assert "'instance' is required" in message
    assert "3 FortiGates configured" in message
    assert "a, b, c" in message


def test_known_name_resolves_to_the_right_client() -> None:
    registry = InstanceRegistry([_cfg("a"), _cfg("b")])

    assert registry.resolve("b").name == "b"  # type: ignore[union-attr]


def test_surrounding_whitespace_is_stripped() -> None:
    registry = InstanceRegistry([_cfg("a"), _cfg("b")])

    assert registry.resolve("  b  ").name == "b"  # type: ignore[union-attr]


async def test_unknown_name_errors_and_lists_configured_names() -> None:
    registry = InstanceRegistry([_cfg("a"), _cfg("b")])

    client = registry.resolve("nope")

    assert isinstance(client, ErrorClient)
    with pytest.raises(FortiOSError) as excinfo:
        await client.cmdb_get("firewall/policy")
    assert "Unknown instance 'nope'" in str(excinfo.value)
    assert "Configured: a, b" in str(excinfo.value)


def test_read_only_flag_reaches_the_client() -> None:
    registry = InstanceRegistry([_cfg("ro", read_only=True), _cfg("rw")])

    assert registry.resolve("ro").read_only is True  # type: ignore[union-attr]
    assert registry.resolve("rw").read_only is False  # type: ignore[union-attr]


@pytest.mark.parametrize(
    "method",
    [
        "cmdb_get",
        "cmdb_delete",
        "monitor_get",
        "log_get",
        "service_get",
    ],
)
async def test_error_client_raises_from_every_no_body_method(method: str) -> None:
    client = ErrorClient("boom", 7)

    with pytest.raises(FortiOSError) as excinfo:
        await getattr(client, method)("some/path")

    assert str(excinfo.value) == "boom"
    assert excinfo.value.status_code == 7


@pytest.mark.parametrize(
    "method", ["cmdb_post", "cmdb_put", "monitor_post", "log_post", "service_post"]
)
async def test_error_client_raises_from_every_body_method(method: str) -> None:
    client = ErrorClient("boom", 7)

    with pytest.raises(FortiOSError):
        await getattr(client, method)("some/path", {"a": 1})


def test_registry_exposes_configs_and_names_in_order() -> None:
    registry = InstanceRegistry([_cfg("z"), _cfg("a")])

    assert registry.names() == ["z", "a"]
    assert [c.name for c in registry.configs] == ["z", "a"]
    assert list(registry.clients) == ["z", "a"]


def test_roster_text_lists_names_descriptions_and_read_only() -> None:
    text = roster_text([_cfg("hq-fw", read_only=True), _cfg("dc-edge")])

    assert "- hq-fw — hq-fw description [READ-ONLY]" in text
    assert "- dc-edge — dc-edge description" in text
    assert "[READ-ONLY]" not in text.split("dc-edge")[1]
    assert "`instance` is required" in text
    assert 'instance="*"' in text


def test_roster_text_for_one_instance_says_instance_may_be_omitted() -> None:
    text = roster_text([_cfg("only-fw")])

    assert "may be omitted" in text


def test_roster_text_with_no_instances_explains_how_to_configure() -> None:
    text = roster_text([])

    assert "No FortiGate instances are configured" in text
    assert "FORTIOS_INSTANCES_FILE" in text


def test_roster_text_never_leaks_a_token() -> None:
    assert "tok" not in roster_text([_cfg("a")])
