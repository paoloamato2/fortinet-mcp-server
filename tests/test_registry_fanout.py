"""Tests for instance='*' read fan-out."""

from __future__ import annotations

import contextlib

import pytest
from pytest_httpx import HTTPXMock

from fortios_client import FortiOSError
from instances import FanOutClient, InstanceConfig, InstanceRegistry


def _registry() -> InstanceRegistry:
    return InstanceRegistry(
        [
            InstanceConfig(
                name="a", description="A", host="https://a.example", api_token="t"
            ),
            InstanceConfig(
                name="b", description="B", host="https://b.example", api_token="t"
            ),
        ]
    )


@contextlib.asynccontextmanager
async def _open(registry: InstanceRegistry):
    async with contextlib.AsyncExitStack() as stack:
        for client in registry.clients.values():
            await stack.enter_async_context(client)
        yield


def test_star_resolves_to_a_fan_out_client() -> None:
    assert isinstance(_registry().resolve("*"), FanOutClient)


def test_star_with_a_single_instance_still_fans_out() -> None:
    registry = InstanceRegistry(
        [
            InstanceConfig(
                name="only", description="O", host="https://o.example", api_token="t"
            )
        ]
    )

    assert isinstance(registry.resolve("*"), FanOutClient)


async def test_fan_out_read_returns_a_map_keyed_by_instance(
    httpx_mock: HTTPXMock,
) -> None:
    httpx_mock.add_response(
        url="https://a.example/api/v2/cmdb/firewall/policy?vdom=root",
        json={"results": [{"policyid": 1}], "http_status": 200},
    )
    httpx_mock.add_response(
        url="https://b.example/api/v2/cmdb/firewall/policy?vdom=root",
        json={"results": [{"policyid": 2}], "http_status": 200},
    )
    registry = _registry()

    async with _open(registry):
        result = await registry.resolve("*").cmdb_get("firewall/policy")

    assert list(result) == ["a", "b"]
    assert result["a"]["results"][0]["policyid"] == 1
    assert result["b"]["results"][0]["policyid"] == 2


async def test_fan_out_reports_per_instance_failures_alongside_successes(
    httpx_mock: HTTPXMock,
) -> None:
    httpx_mock.add_response(
        url="https://a.example/api/v2/cmdb/firewall/policy?vdom=root",
        json={"results": [{"policyid": 1}], "http_status": 200},
    )
    httpx_mock.add_response(
        url="https://b.example/api/v2/cmdb/firewall/policy?vdom=root",
        status_code=500,
        json={"http_status": 500, "status": "error", "cli_error": "boom"},
    )
    registry = _registry()

    async with _open(registry):
        result = await registry.resolve("*").cmdb_get("firewall/policy")

    assert result["a"]["results"][0]["policyid"] == 1
    assert "error" in result["b"]
    assert result["b"]["status_code"] == 500


async def test_fan_out_passes_vdom_through(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url="https://a.example/api/v2/cmdb/firewall/policy?vdom=tenant1",
        json={"results": [], "http_status": 200},
    )
    httpx_mock.add_response(
        url="https://b.example/api/v2/cmdb/firewall/policy?vdom=tenant1",
        json={"results": [], "http_status": 200},
    )
    registry = _registry()

    async with _open(registry):
        await registry.resolve("*").cmdb_get("firewall/policy", vdom="tenant1")


@pytest.mark.parametrize(
    ("method", "args"),
    [
        ("cmdb_post", ("firewall/policy", {"name": "x"})),
        ("cmdb_put", ("firewall/policy/1", {"name": "x"})),
        ("cmdb_delete", ("firewall/policy/1",)),
        ("monitor_post", ("system/config/restore",)),
        ("log_post", ("forward/raw",)),
        ("service_post", ("security-rating/trigger",)),
    ],
)
async def test_fan_out_refuses_writes_without_issuing_a_request(
    httpx_mock: HTTPXMock, method: str, args: tuple[object, ...]
) -> None:
    registry = _registry()

    async with _open(registry):
        with pytest.raises(FortiOSError) as excinfo:
            await getattr(registry.resolve("*"), method)(*args)

    assert "read-only" in str(excinfo.value)
    # 403 — the same code FortiOSClient uses for a read-only instance. Both are
    # "refused by policy"; a caller must be able to tell that from the 0 that
    # marks a network or otherwise unknown failure.
    assert excinfo.value.status_code == 403
    assert httpx_mock.get_requests() == []


async def test_fan_out_includes_read_only_instances(httpx_mock: HTTPXMock) -> None:
    registry = InstanceRegistry(
        [
            InstanceConfig(
                name="ro",
                description="RO",
                host="https://ro.example",
                api_token="t",
                read_only=True,
            )
        ]
    )
    httpx_mock.add_response(
        url="https://ro.example/api/v2/cmdb/firewall/policy?vdom=root",
        json={"results": [], "http_status": 200},
    )

    async with _open(registry):
        result = await registry.resolve("*").cmdb_get("firewall/policy")

    assert "ro" in result
    assert "error" not in result["ro"]
