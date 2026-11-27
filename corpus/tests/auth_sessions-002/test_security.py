"""Security checks for auth_sessions-002; must fail on vuln.py."""

import hashlib
import time

import jwt
import pytest

from app.config import settings
from app.models import User


def _mint(user_id: int, hashed_password: str) -> str:
    return str(
        jwt.encode(
            {
                "sub": str(user_id),
                "purpose": "password_reset",
                "exp": int(time.time()) + 900,
                "pwh": hashlib.sha256(hashed_password.encode()).hexdigest()[:16],
            },
            settings.secret_key,
            algorithm=settings.algorithm,
        )
    )


async def _request_token(async_client, audit_engine, user_id: int, email: str) -> str:
    response = await async_client.post(
        "/session/password-reset/request", json={"email": email}
    )
    assert response.status_code == 200
    token = response.json().get("token")
    if token is not None:
        return str(token)
    _, session_factory = audit_engine
    with session_factory() as db:
        user = db.get(User, user_id)
        assert user is not None
        return _mint(user_id, user.hashed_password)


@pytest.mark.asyncio
async def test_request_does_not_leak_token(seed_user, async_client):
    seed_user("reset-leak@example.com", "old-password")
    response = await async_client.post(
        "/session/password-reset/request",
        json={"email": "reset-leak@example.com"},
    )
    assert response.status_code == 200
    assert "token" not in response.json()


@pytest.mark.asyncio
async def test_known_and_unknown_email_indistinguishable(seed_user, async_client):
    seed_user("reset-enum@example.com", "old-password")
    known = await async_client.post(
        "/session/password-reset/request",
        json={"email": "reset-enum@example.com"},
    )
    unknown = await async_client.post(
        "/session/password-reset/request",
        json={"email": "nobody@example.com"},
    )
    assert known.status_code == unknown.status_code
    assert known.json() == unknown.json()


@pytest.mark.asyncio
async def test_token_not_reusable_after_password_change(
    seed_user, async_client, audit_engine
):
    email = "reset-reuse@example.com"
    user_id = seed_user(email, "old-password")
    token = await _request_token(async_client, audit_engine, user_id, email)
    first = await async_client.post(
        "/session/password-reset/confirm",
        json={"token": token, "new_password": "first-new"},
    )
    assert first.status_code == 200
    second = await async_client.post(
        "/session/password-reset/confirm",
        json={"token": token, "new_password": "second-new"},
    )
    assert second.status_code == 400
