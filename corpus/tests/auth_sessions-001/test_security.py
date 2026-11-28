"""Security checks for auth_sessions-001; must fail on vuln.py."""

import hashlib

import pytest


@pytest.mark.asyncio
async def test_unknown_and_wrong_password_are_indistinguishable(
    seed_user, async_client
):
    seed_user("signin-enum@example.com", "correct-horse")
    unknown = await async_client.post(
        "/session/signin",
        json={"email": "nobody@example.com", "password": "whatever"},
    )
    wrong = await async_client.post(
        "/session/signin",
        json={"email": "signin-enum@example.com", "password": "wrong"},
    )
    assert unknown.status_code == wrong.status_code
    assert unknown.json() == wrong.json()


@pytest.mark.asyncio
async def test_weak_sha256_hash_rejected(seed_user, async_client):
    weak = hashlib.sha256(b"weak-pass").hexdigest()
    seed_user("signin-weak@example.com", hashed_password=weak)
    response = await async_client.post(
        "/session/signin",
        json={"email": "signin-weak@example.com", "password": "weak-pass"},
    )
    assert response.status_code == 401
