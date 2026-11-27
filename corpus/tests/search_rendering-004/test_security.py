"""Security checks for search_rendering-004; must fail on vuln.py."""

import pytest


@pytest.mark.asyncio
async def test_boolean_bypass_returns_no_rows(async_client):
    response = await async_client.get(
        "/search/products", params={"q": "nonexistent_xyz' OR '1'='1"}
    )
    assert response.status_code < 500
    assert response.json()["items"] == []


@pytest.mark.asyncio
async def test_union_select_does_not_leak_users(async_client):
    payload = "' UNION SELECT 1, email, hashed_password, 0 FROM users--"
    response = await async_client.get("/search/products", params={"q": payload})
    assert response.status_code < 500
    body = response.text
    assert "owner@example.com" not in body
    assert "other@example.com" not in body
    assert "not-a-real-hash" not in body
