"""Security checks for search_rendering-005; must fail on vuln.py."""

import pytest


@pytest.mark.asyncio
async def test_arithmetic_ssti_is_not_evaluated(async_client):
    response = await async_client.get(
        "/search/custom-banner",
        params={"q": "Widget", "banner": "{{7*7}}"},
    )
    assert response.status_code == 200
    assert "49" not in response.text
    assert "{{7*7}}" in response.text


@pytest.mark.asyncio
async def test_string_ssti_is_not_evaluated(async_client):
    response = await async_client.get(
        "/search/custom-banner",
        params={"q": "Widget", "banner": "{{7*'7'}}"},
    )
    assert response.status_code == 200
    assert "7777777" not in response.text
