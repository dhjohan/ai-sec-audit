"""Functional checks for auth_sessions-002; must pass on secure.py and vuln.py."""

import pytest

from app.core.mailer import outbox
from app.models import User


@pytest.mark.asyncio
async def test_reset_delivers_token_and_changes_password(
    seed_user, async_client, audit_engine
):
    email = "reset-ok@example.com"
    user_id = seed_user(email, "old-password")
    outbox.clear()
    response = await async_client.post(
        "/session/password-reset/request", json={"email": email}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "sent"
    assert len(outbox) == 1
    assert outbox[0].to == email
    token = outbox[0].token
    assert token

    confirm = await async_client.post(
        "/session/password-reset/confirm",
        json={"token": token, "new_password": "new-password"},
    )
    assert confirm.status_code == 200
    assert confirm.json() == {"status": "password updated"}

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
