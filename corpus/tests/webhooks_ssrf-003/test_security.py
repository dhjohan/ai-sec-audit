"""Security checks for webhooks_ssrf-003; must fail on vuln.py."""

import pytest

INTERNAL_ENTITY = (
    '<!DOCTYPE rss [<!ENTITY xxe "EXPANDED_SECRET_MARKER">]>'
    "<rss><channel><item><title>&xxe;</title>"
    "<link>https://example.com/x</link></item></channel></rss>"
)

EXTERNAL_ENTITY = (
    '<!DOCTYPE rss [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    "<rss><channel><item><title>&xxe;</title>"
    "<link>https://example.com/x</link></item></channel></rss>"
)


@pytest.mark.asyncio
async def test_internal_entity_not_expanded(async_client):
    response = await async_client.post(
        "/integrations/rss-import", json={"feed_xml": INTERNAL_ENTITY}
    )
    assert "EXPANDED_SECRET_MARKER" not in response.text


@pytest.mark.asyncio
async def test_external_entity_not_read(async_client):
    response = await async_client.post(
        "/integrations/rss-import", json={"feed_xml": EXTERNAL_ENTITY}
    )
    assert "root:" not in response.text
    assert "file://" not in response.text
