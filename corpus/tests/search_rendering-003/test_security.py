"""Security checks for search_rendering-003; must fail on vuln.py."""

import pytest


async def _first_product_id(async_client) -> int:
    listing = await async_client.get("/api/v1/products")
    assert listing.status_code == 200
    return listing.json()[0]["id"]


@pytest.mark.asyncio
async def test_svg_payload_is_escaped(async_client):
    product_id = await _first_product_id(async_client)
    payload = "<svg onload=alert(1)>"
    response = await async_client.post(
        "/preview/product",
        json={"product_id": product_id, "highlight": payload},
    )
    assert response.status_code == 200
    assert "<svg" not in response.text
    assert "&lt;svg" in response.text


@pytest.mark.asyncio
async def test_script_payload_is_escaped(async_client):
    product_id = await _first_product_id(async_client)
    payload = "<script>alert(1)</script>"
    response = await async_client.post(
        "/preview/product",
        json={"product_id": product_id, "highlight": payload},
    )
    assert response.status_code == 200
    assert payload not in response.text
    assert "&lt;script&gt;" in response.text
