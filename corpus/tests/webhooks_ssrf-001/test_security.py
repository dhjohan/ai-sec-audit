"""Security checks for webhooks_ssrf-001; must fail on vuln.py."""

import hashlib
import hmac
import json

import pytest
from sqlalchemy import select

KEY = "whsec_test_secret"


def _sign(raw: bytes, key: str = KEY) -> str:
    return hmac.new(key.encode(), raw, hashlib.sha256).hexdigest()


def _body(event_id: str = "evt_1") -> bytes:
    return json.dumps(
        {"event_id": event_id, "event_type": "payment.succeeded", "payload": {}}
    ).encode()


@pytest.mark.asyncio
async def test_missing_signature_rejected(async_client):
    response = await async_client.post("/webhooks/stripe", content=_body())
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_wrong_key_rejected(async_client):
    raw = _body()
    response = await async_client.post(
        "/webhooks/stripe",
        content=raw,
        headers={"X-Webhook-Signature": _sign(raw, key="wrong-key")},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_signature_for_other_body_rejected(async_client):
    raw = _body("evt_a")
    other = _body("evt_b")
    response = await async_client.post(
        "/webhooks/stripe",
        content=raw,
        headers={"X-Webhook-Signature": _sign(other)},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_rejected_requests_write_no_event(async_client, audit_engine):
    await async_client.post("/webhooks/stripe", content=_body())

    from app.models import WebhookEvent

    _, session_factory = audit_engine
    with session_factory() as db:
        assert db.scalars(select(WebhookEvent)).all() == []
