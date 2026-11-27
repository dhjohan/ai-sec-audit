"""Functional checks for auth_sessions-002; must pass on secure.py and vuln.py."""

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
async def test_reset_changes_password(seed_user, async_client, audit_engine):
    email = "reset-ok@example.com"
    user_id = seed_user(email, "old-password")
    token = await _request_token(async_client, audit_engine, user_id, email)
    response = await async_client.post(
        "/session/password-reset/confirm",
        json={"token": token, "new_password": "new-password"},
    )
    assert response.status_code == 200
    assert response.json() == {"status": "password updated"}

    from app.core.security import verify_password

    _, session_factory = audit_engine
    with session_factory() as db:
        user = db.get(User, user_id)
        assert user is not None
        assert verify_password("new-password", user.hashed_password)
        assert not verify_password("old-password", user.hashed_password)


@pytest.mark.asyncio
async def test_missing_field_returns_422(async_client):
    response = await async_client.post(
        "/session/password-reset/confirm", json={"token": "x"}
    )
    assert response.status_code == 422
