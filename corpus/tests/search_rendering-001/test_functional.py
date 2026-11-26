"""Functional checks for search_rendering-001; must pass on secure.py and vuln.py."""

import pytest


@pytest.mark.asyncio
async def test_query_returns_query_and_matching_product(async_client):
    response = await async_client.get("/search/html", params={"q": "Widget"})
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Widget" in response.text
    assert "Blue Widget" in response.text
    assert "Red Gadget" not in response.text


@pytest.mark.asyncio
async def test_empty_query_lists_every_product(async_client):
    response = await async_client.get("/search/html")
    assert response.status_code == 200
    assert "Blue Widget" in response.text
    assert "Red Gadget" in response.text


@pytest.mark.asyncio
async def test_non_matching_query_is_empty(async_client):
    response = await async_client.get("/search/html", params={"q": "zzz-not-here"})
    assert response.status_code == 200
    assert "Blue Widget" not in response.text
    assert "Red Gadget" not in response.text
