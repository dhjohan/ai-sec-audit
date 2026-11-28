"""Functional checks for auth_sessions-005; must pass on secure.py and vuln.py."""

from http.cookies import SimpleCookie

import pytest

from app.core.security import decode_access_token


def _cookie_value(response) -> str:
    cookies = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    return cookies["session_token"].value


@pytest.mark.asyncio
async def test_cookie_login_sets_token(seed_user, async_client):
    user_id = seed_user("cookie-ok@example.com", "correct-horse")
    response = await async_client.post(
        "/session/cookie-login",
        json={"email": "cookie-ok@example.com", "password": "correct-horse"},
    )
    assert response.status_code == 200
    assert response.json()["user"] == {
        "id": user_id,
        "email": "cookie-ok@example.com",
    }
    token = _cookie_value(response)
    assert int(decode_access_token(token)["sub"]) == user_id


@pytest.mark.asyncio
async def test_wrong_password_returns_401(seed_user, async_client):
    seed_user("cookie-bad@example.com", "correct-horse")
    response = await async_client.post(
        "/session/cookie-login",
        json={"email": "cookie-bad@example.com", "password": "wrong"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_missing_field_returns_422(async_client):
    response = await async_client.post(
        "/session/cookie-login", json={"email": "nobody@example.com"}
    )
    assert response.status_code == 422
