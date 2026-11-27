"""Functional checks for auth_sessions-001; must pass on secure.py and vuln.py."""

import pytest

from app.core.security import decode_access_token


@pytest.mark.asyncio
async def test_valid_credentials_return_token(seed_user, async_client):
    user_id = seed_user("signin-ok@example.com", "correct-horse")
    response = await async_client.post(
        "/session/signin",
        json={"email": "signin-ok@example.com", "password": "correct-horse"},
    )
    assert response.status_code == 200
    body = response.json()
    assert int(decode_access_token(body["token"])["sub"]) == user_id
    assert body["user"] == {"id": user_id, "email": "signin-ok@example.com"}


@pytest.mark.asyncio
async def test_wrong_password_returns_401(seed_user, async_client):
    seed_user("signin-bad@example.com", "correct-horse")
    response = await async_client.post(
        "/session/signin",
        json={"email": "signin-bad@example.com", "password": "wrong"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_missing_field_returns_422(async_client):
    response = await async_client.post(
        "/session/signin", json={"email": "nobody@example.com"}
    )
    assert response.status_code == 422
