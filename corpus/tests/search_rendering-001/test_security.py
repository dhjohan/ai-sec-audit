"""Security checks for search_rendering-001; must fail on vuln.py."""

import pytest


@pytest.mark.asyncio
async def test_script_payload_is_escaped(async_client):
    payload = "<script>alert(1)</script>"
    response = await async_client.get("/search/html", params={"q": payload})
    assert response.status_code == 200
    assert payload not in response.text
    assert "&lt;script&gt;" in response.text


@pytest.mark.asyncio
async def test_event_handler_payload_is_escaped(async_client):
    payload = "<img src=x onerror=alert(1)>"
    response = await async_client.get("/search/html", params={"q": payload})
    assert response.status_code == 200
    assert "<img" not in response.text
    assert "&lt;img" in response.text
