"""Security checks for auth_sessions-003; must fail on vuln.py."""

import base64
import json
import time

import jwt
import pytest

from app.config import settings


def _b64(value: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()


def _token(secret: str, user_id: int, exp_offset: int = 900) -> str:
    return str(
        jwt.encode(
            {"sub": str(user_id), "exp": int(time.time()) + exp_offset},
            secret,
            algorithm="HS256",
        )
    )


async def _call(async_client, token: str):
    return await async_client.post(
        "/session/jwt-verify", headers={"Authorization": f"Bearer {token}"}
    )


@pytest.mark.asyncio
async def test_wrong_secret_rejected(seed_user, async_client):
    user_id = seed_user("jwt-wrong-secret@example.com", "correct-horse")
    response = await _call(async_client, _token("wrong-secret", user_id))
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_hardcoded_secret_rejected(seed_user, async_client):
    user_id = seed_user("jwt-hardcoded@example.com", "correct-horse")
    response = await _call(async_client, _token("secret", user_id))
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_alg_none_rejected(seed_user, async_client):
    user_id = seed_user("jwt-none@example.com", "correct-horse")
    header = _b64({"alg": "none", "typ": "JWT"})
    payload = _b64({"sub": str(user_id), "exp": int(time.time()) + 900})
    response = await _call(async_client, f"{header}.{payload}.")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_expired_token_rejected(seed_user, async_client):
    user_id = seed_user("jwt-expired@example.com", "correct-horse")
    response = await _call(
        async_client, _token(settings.secret_key, user_id, exp_offset=-10)
    )
    assert response.status_code == 401
