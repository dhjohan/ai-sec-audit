"""Functional checks for webhooks_ssrf-002; must pass on secure.py and vuln.py."""

import pytest


@pytest.mark.asyncio
async def test_preview_returns_title(async_client, fake_network):
    response = await async_client.post(
        "/integrations/link-preview", json={"url": "https://example.com/page"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["url"] == "https://example.com/page"
    assert body["title"] == "Example Title"
    assert fake_network.calls == [("GET", "https://example.com/page")]


@pytest.mark.asyncio
async def test_missing_title_returns_null(async_client, fake_network):
    fake_network.html = "<html><body>nothing here</body></html>"
    response = await async_client.post(
        "/integrations/link-preview", json={"url": "https://example.com/no-title"}
    )
    assert response.status_code == 200
    assert response.json()["title"] is None


@pytest.mark.asyncio
async def test_unsupported_scheme_rejected(async_client, fake_network):
    response = await async_client.post(
        "/integrations/link-preview", json={"url": "ftp://example.com/file"}
    )
    assert response.status_code == 400
    assert fake_network.calls == []


@pytest.mark.asyncio
async def test_malformed_url_rejected(async_client, fake_network):
    response = await async_client.post(
        "/integrations/link-preview", json={"url": "not-a-url"}
    )
    assert response.status_code == 400
    assert fake_network.calls == []


@pytest.mark.asyncio
async def test_fetch_failure_returns_502(async_client, fake_network):
    fake_network.error = RuntimeError("boom")
    response = await async_client.post(
        "/integrations/link-preview", json={"url": "https://example.com/page"}
    )
    assert response.status_code == 502
