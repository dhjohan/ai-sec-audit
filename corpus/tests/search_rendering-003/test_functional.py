"""Functional checks for search_rendering-003; must pass on secure.py and vuln.py."""

import pytest


async def _first_product_id(async_client) -> int:
    listing = await async_client.get("/api/v1/products")
    assert listing.status_code == 200
    return listing.json()[0]["id"]


@pytest.mark.asyncio
async def test_preview_returns_product_and_highlight(async_client):
    product_id = await _first_product_id(async_client)
    response = await async_client.post(
        "/preview/product",
        json={"product_id": product_id, "highlight": "Sale"},
    )
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Blue Widget" in response.text
    assert "Sale" in response.text


@pytest.mark.asyncio
async def test_missing_product_returns_404(async_client):
    response = await async_client.post(
        "/preview/product",
        json={"product_id": 999999, "highlight": "Sale"},
    )
    assert response.status_code == 404
