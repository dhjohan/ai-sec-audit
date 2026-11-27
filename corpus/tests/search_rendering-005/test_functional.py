"""Functional checks for search_rendering-005; must pass on secure.py and vuln.py."""

import pytest


@pytest.mark.asyncio
async def test_custom_banner_substitutes_placeholders(async_client):
    response = await async_client.get(
        "/search/custom-banner",
        params={"q": "Widget", "banner": "Found {{ count }} for {{ query }}"},
    )
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Found 1 for Widget" in response.text
    assert "Blue Widget" in response.text


@pytest.mark.asyncio
async def test_default_banner_is_used(async_client):
    response = await async_client.get("/search/custom-banner", params={"q": "Widget"})
    assert response.status_code == 200
    assert "Results for Widget (1)" in response.text
    assert "Blue Widget" in response.text


@pytest.mark.asyncio
async def test_empty_query_counts_every_product(async_client):
    response = await async_client.get(
        "/search/custom-banner",
        params={"banner": "Total {{ count }}"},
    )
    assert response.status_code == 200
    assert "Total 2" in response.text
