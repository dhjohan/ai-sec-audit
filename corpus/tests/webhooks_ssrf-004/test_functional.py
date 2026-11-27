"""Functional checks for webhooks_ssrf-004; must pass on secure.py and vuln.py."""

import pytest

from app.config import settings
from app.core.security import create_access_token

CALLBACK = "/integrations/oauth/callback"


def _cookies(user_id: int = 1) -> dict[str, str]:
    return {settings.session_cookie_name: create_access_token(str(user_id))}


@pytest.mark.asyncio
async def test_valid_callback_redirects_to_next(async_client):
    response = await async_client.get(
        CALLBACK,
        params={"code": "abc", "state": "state-1", "next": "/dashboard"},
        cookies=_cookies(1),
    )
    assert response.status_code == 302
    assert response.headers["location"] == "/dashboard"


@pytest.mark.asyncio
async def test_default_next_is_root(async_client):
    response = await async_client.get(
        CALLBACK,
        params={"code": "abc", "state": "state-1"},
        cookies=_cookies(1),
    )
    assert response.status_code == 302
    assert response.headers["location"] == "/"


@pytest.mark.asyncio
async def test_requires_session(async_client):
    response = await async_client.get(
        CALLBACK, params={"code": "abc", "state": "state-1"}
    )
    assert response.status_code == 401
