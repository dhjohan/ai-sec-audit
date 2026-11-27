"""Security checks for auth_sessions-004; must fail on vuln.py."""

import pytest


@pytest.mark.asyncio
async def test_lockout_after_repeated_failures(seed_otp, async_client):
    email = "mfa-lockout@example.com"
    seed_otp(email, "123456")
    for _ in range(12):
        await async_client.post(
            "/session/mfa-verify", json={"email": email, "code": "000000"}
        )
    response = await async_client.post(
        "/session/mfa-verify", json={"email": email, "code": "123456"}
    )
    assert response.status_code in (423, 429)
