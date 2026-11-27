"""Functional checks for webhooks_ssrf-001; must pass on secure.py and vuln.py."""

import hashlib
import hmac
import json

import pytest
from sqlalchemy import select

KEY = "whsec_test_secret"


def _sign(raw: bytes, key: str = KEY) -> str:
    return hmac.new(key.encode(), raw, hashlib.sha256).hexdigest()


@pytest.mark.asyncio
async def test_valid_signature_stores_event(async_client, audit_engine):
    body = {
        "event_id": "evt_1",
        "event_type": "payment.succeeded",
        "payload": {"amount": 100},
    }
    raw = json.dumps(body).encode()
    response = await async_client.post(
        "/webhooks/stripe", content=raw, headers={"X-Webhook-Signature": _sign(raw)}
    )
    assert response.status_code == 202
    data = response.json()
    assert data["event_id"] == "evt_1"
    assert isinstance(data["webhook_id"], int)

    from app.models import WebhookEvent

    _, session_factory = audit_engine
    with session_factory() as db:
        events = db.scalars(select(WebhookEvent)).all()
        assert len(events) == 1
        assert events[0].source == "stripe"
        assert events[0].event_type == "payment.succeeded"
        assert events[0].payload["event_id"] == "evt_1"
        assert events[0].processed is True


@pytest.mark.asyncio
async def test_invalid_json_signed_returns_422(async_client):
    raw = b"{not json"
    response = await async_client.post(
        "/webhooks/stripe", content=raw, headers={"X-Webhook-Signature": _sign(raw)}
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_missing_field_signed_returns_422(async_client):
    raw = json.dumps({"event_id": "evt_2", "payload": {}}).encode()
    response = await async_client.post(
        "/webhooks/stripe", content=raw, headers={"X-Webhook-Signature": _sign(raw)}
    )
    assert response.status_code == 422
