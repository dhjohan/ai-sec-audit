"""Functional checks for search_rendering-002; must pass on secure.py and vuln.py."""

import pytest


@pytest.mark.asyncio
async def test_catalog_renders_term_and_matches(async_client):
    response = await async_client.get("/catalog/render", params={"q": "Widget"})
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Widget" in response.text
    assert "Blue Widget" in response.text
    assert "Red Gadget" not in response.text


@pytest.mark.asyncio
async def test_empty_query_lists_every_product(async_client):
    response = await async_client.get("/catalog/render")
    assert response.status_code == 200
    assert "Blue Widget" in response.text
    assert "Red Gadget" in response.text
