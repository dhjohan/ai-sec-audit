"""Security checks for auth_sessions-005; must fail on vuln.py."""

import pytest


@pytest.mark.asyncio
async def test_session_cookie_flags(seed_user, async_client):
    seed_user("cookie-flags@example.com", "correct-horse")
    response = await async_client.post(
        "/session/cookie-login",
        json={"email": "cookie-flags@example.com", "password": "correct-horse"},
    )
    assert response.status_code == 200
    header = response.headers.get("set-cookie", "").lower()
    assert "session_token=" in header
    assert "httponly" in header
    assert "secure" in header
    assert "samesite=lax" in header or "samesite=strict" in header
