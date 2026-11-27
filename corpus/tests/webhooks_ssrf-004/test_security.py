"""Security checks for webhooks_ssrf-004; must fail on vuln.py."""

import pytest

from app.config import settings
from app.core.security import create_access_token

CALLBACK = "/integrations/oauth/callback"


def _cookies(user_id: int = 1) -> dict[str, str]:
    return {settings.session_cookie_name: create_access_token(str(user_id))}


@pytest.mark.asyncio
async def test_state_mismatch_rejected(async_client):
    response = await async_client.get(
        CALLBACK,
        params={"code": "abc", "state": "state-2", "next": "/dashboard"},
        cookies=_cookies(1),
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_absolute_next_rejected(async_client):
    response = await async_client.get(
        CALLBACK,
        params={
            "code": "abc",
            "state": "state-1",
            "next": "https://evil.example/x",
        },
        cookies=_cookies(1),
    )
    assert response.status_code == 400
    assert "evil.example" not in response.headers.get("location", "")


@pytest.mark.asyncio
async def test_scheme_relative_next_rejected(async_client):
    response = await async_client.get(
        CALLBACK,
        params={"code": "abc", "state": "state-1", "next": "//evil.example/x"},
        cookies=_cookies(1),
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_backslash_next_rejected(async_client):
    response = await async_client.get(
        CALLBACK,
        params={"code": "abc", "state": "state-1", "next": "/\\evil.example"},
        cookies=_cookies(1),
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_safe_next_allowed(async_client):
    response = await async_client.get(
        CALLBACK,
        params={"code": "abc", "state": "state-1", "next": "/settings"},
        cookies=_cookies(1),
    )
    assert response.status_code == 302
    assert response.headers["location"] == "/settings"
