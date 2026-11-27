"""Functional checks for auth_sessions-004; must pass on secure.py and vuln.py."""

import pytest


@pytest.mark.asyncio
async def test_matching_code_verifies(seed_otp, async_client):
    email = "mfa-ok@example.com"
    seed_otp(email, "654321")
    response = await async_client.post(
        "/session/mfa-verify", json={"email": email, "code": "654321"}
    )
    assert response.status_code == 200
    assert response.json() == {"verified": True}


@pytest.mark.asyncio
async def test_wrong_code_returns_401(seed_otp, async_client):
    email = "mfa-wrong@example.com"
    seed_otp(email, "654321")
    response = await async_client.post(
        "/session/mfa-verify", json={"email": email, "code": "000000"}
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_missing_field_returns_422(async_client):
    response = await async_client.post(
        "/session/mfa-verify", json={"email": "nobody@example.com"}
    )
    assert response.status_code == 422
