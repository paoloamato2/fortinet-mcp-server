"""Tests for the per-instance read-only guard."""

from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from fortios_client import FortiOSClient, FortiOSError


def _client(read_only: bool) -> FortiOSClient:
    return FortiOSClient(
        host="https://fw.example",
        api_token="tok",
        name="hq-fw",
        read_only=read_only,
    )


async def test_reads_are_allowed_on_a_read_only_instance(
    httpx_mock: HTTPXMock,
) -> None:
    httpx_mock.add_response(
        url="https://fw.example/api/v2/cmdb/firewall/policy?vdom=root",
        json={"results": [], "http_status": 200},
    )
    async with _client(read_only=True) as client:
        assert await client.cmdb_get("firewall/policy") == {
            "results": [],
            "http_status": 200,
        }


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
async def test_writes_are_refused_without_issuing_a_request(
    httpx_mock: HTTPXMock, method: str, args: tuple[object, ...]
) -> None:
    async with _client(read_only=True) as client:
        with pytest.raises(FortiOSError) as excinfo:
            await getattr(client, method)(*args)

    assert excinfo.value.status_code == 403
    assert "read-only" in str(excinfo.value)
    assert "hq-fw" in str(excinfo.value)
    assert httpx_mock.get_requests() == []


async def test_writes_are_allowed_when_not_read_only(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url="https://fw.example/api/v2/cmdb/firewall/policy?vdom=root",
        json={"http_status": 200, "mkey": 7},
    )
    async with _client(read_only=False) as client:
        result = await client.cmdb_post("firewall/policy", {"name": "x"})

    assert result["mkey"] == 7
