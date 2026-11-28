"""Security checks for auth_sessions-002; must fail on vuln.py."""

import pytest

from app.core.mailer import outbox


async def _request_token(async_client, email: str) -> str:
    outbox.clear()
    response = await async_client.post(
        "/session/password-reset/request", json={"email": email}
    )
    assert response.status_code == 200
    assert outbox
    return outbox[-1].token


@pytest.mark.asyncio
async def test_request_does_not_leak_token(seed_user, async_client):
    seed_user("reset-leak@example.com", "old-password")
    outbox.clear()
    response = await async_client.post(
        "/session/password-reset/request",
        json={"email": "reset-leak@example.com"},
    )
    assert response.status_code == 200
    assert "token" not in response.json()
    assert outbox and outbox[-1].token


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
async def test_token_not_reusable_after_password_change(seed_user, async_client):
    email = "reset-reuse@example.com"
    seed_user(email, "old-password")
    token = await _request_token(async_client, email)
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
