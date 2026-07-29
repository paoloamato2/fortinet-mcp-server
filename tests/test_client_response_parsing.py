"""Bodies that are JSON in structure but not valid UTF-8 must still parse.

Live capture from fw-itd-inet (FortiOS 7.6.6, FortiAP FP231G): 7 of 12
``monitor/wifi/client`` responses contained raw non-UTF-8 bytes inside
``triangulation_regions[].wtp_id`` -- unsanitised scan memory such as
``b'"\xc4\xff\xff\xff#"'`` -- while the surrounding JSON stayed well formed.
A strict decode turned each of those into a hard ``Non-JSON response`` error;
substituting the bad bytes recovered all 7 in full.
"""

from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from fortios_client import FortiOSClient, FortiOSError


def _client() -> FortiOSClient:
    return FortiOSClient(host="https://fw.example", api_token="tok", name="hq-fw")


async def test_invalid_utf8_inside_a_string_is_replaced_not_fatal(
    httpx_mock: HTTPXMock,
) -> None:
    body = (
        b'{"http_method":"GET","results":[{"mac":"00:1d:63:13:59:3b",'
        b'"triangulation_regions":[{"wtp_id":"\xc4\xff\xff\xff#","rssi":0}]}],'
        b'"status":"success","http_status":200}'
    )
    httpx_mock.add_response(
        url="https://fw.example/api/v2/monitor/wifi/client?vdom=root",
        content=body,
        headers={"content-type": "application/json"},
    )

    async with _client() as client:
        payload = await client.monitor_get("wifi/client")

    assert payload["status"] == "success"
    row = payload["results"][0]
    assert row["mac"] == "00:1d:63:13:59:3b"
    assert row["triangulation_regions"][0]["wtp_id"] == "����#"


async def test_a_body_that_is_not_json_at_all_still_raises(
    httpx_mock: HTTPXMock,
) -> None:
    httpx_mock.add_response(
        url="https://fw.example/api/v2/monitor/wifi/client?vdom=root",
        content=b"<html>entering error mode</html>",
        headers={"content-type": "text/html"},
    )

    async with _client() as client:
        with pytest.raises(FortiOSError) as excinfo:
            await client.monitor_get("wifi/client")

    assert "Non-JSON response" in str(excinfo.value)
    assert excinfo.value.status_code == 200
