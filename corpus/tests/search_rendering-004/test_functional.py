"""Functional checks for search_rendering-004; must pass on secure.py and vuln.py."""

import pytest

REQUIRED_KEYS = {"id", "name", "sku", "price_cents"}


@pytest.mark.asyncio
async def test_filters_by_name_substring(async_client):
    response = await async_client.get("/search/products", params={"q": "Widget"})
    assert response.status_code == 200
    body = response.json()
    assert len(body["items"]) == 1
    item = body["items"][0]
    assert set(item) == REQUIRED_KEYS
    assert item["name"] == "Blue Widget"
    assert item["sku"] == "WIDGET-BLUE"
    assert item["price_cents"] == 1000


@pytest.mark.asyncio
async def test_empty_parameters_return_all_products(async_client):
    response = await async_client.get("/search/products")
    assert response.status_code == 200
    assert len(response.json()["items"]) == 2


@pytest.mark.asyncio
async def test_sku_filter_and_non_match(async_client):
    filtered = await async_client.get("/search/products", params={"sku": "GADGET"})
    assert filtered.status_code == 200
    assert [item["sku"] for item in filtered.json()["items"]] == ["GADGET-RED"]

    missing = await async_client.get("/search/products", params={"q": "zzz-not-here"})
    assert missing.status_code == 200
    assert missing.json()["items"] == []
