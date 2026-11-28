"""Functional checks for auth_sessions-003; must pass on secure.py and vuln.py."""

import pytest

from app.core.security import create_access_token


@pytest.mark.asyncio
async def test_valid_token_returns_user(seed_user, async_client):
    user_id = seed_user("jwt-ok@example.com", "correct-horse")
    token = create_access_token(str(user_id))
    response = await async_client.post(
        "/session/jwt-verify", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json() == {"user_id": user_id, "email": "jwt-ok@example.com"}


@pytest.mark.asyncio
async def test_missing_header_returns_401(async_client):
    response = await async_client.post("/session/jwt-verify")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_malformed_token_returns_401(seed_user, async_client):
    seed_user("jwt-bad@example.com", "correct-horse")
    response = await async_client.post(
        "/session/jwt-verify", headers={"Authorization": "Bearer not-a-jwt"}
    )
    assert response.status_code == 401
