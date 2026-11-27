"""Functional checks for webhooks_ssrf-003; must pass on secure.py and vuln.py."""

import pytest

FEED = """<?xml version="1.0"?>
<rss version="2.0"><channel>
<item><title>First</title><link>https://example.com/1</link></item>
<item><title>Second</title><link>https://example.com/2</link></item>
</channel></rss>"""


@pytest.mark.asyncio
async def test_two_items_parsed_in_order(async_client):
    response = await async_client.post(
        "/integrations/rss-import", json={"feed_xml": FEED}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 2
    assert body["items"] == [
        {"title": "First", "link": "https://example.com/1"},
        {"title": "Second", "link": "https://example.com/2"},
    ]


@pytest.mark.asyncio
async def test_empty_channel_returns_zero(async_client):
    feed = "<rss version='2.0'><channel></channel></rss>"
    response = await async_client.post(
        "/integrations/rss-import", json={"feed_xml": feed}
    )
    assert response.status_code == 200
    assert response.json() == {"items": [], "count": 0}


@pytest.mark.asyncio
async def test_malformed_xml_returns_400(async_client):
    response = await async_client.post(
        "/integrations/rss-import", json={"feed_xml": "<rss><channel>"}
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_missing_field_returns_422(async_client):
    response = await async_client.post("/integrations/rss-import", json={})
    assert response.status_code == 422
