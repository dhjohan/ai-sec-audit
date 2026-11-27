"""Functional checks for webhooks_ssrf-005; must pass on secure.py and vuln.py."""

import pytest
from sqlalchemy import select

CALLBACK = "https://hooks.example.com/order"


@pytest.mark.asyncio
async def test_dispatches_to_allowed_callback(
    async_client, fake_network, seed_order, audit_engine
):
    response = await async_client.post(
        "/webhooks/dispatch",
        json={"order_id": seed_order, "callback_url": CALLBACK},
    )
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "delivered"
    assert isinstance(body["event_id"], int)
    assert ("POST", CALLBACK) in fake_network.calls

    from app.models import WebhookEvent

    _, session_factory = audit_engine
    with session_factory() as db:
        events = db.scalars(select(WebhookEvent)).all()
        assert len(events) == 1
        assert events[0].source == "dispatch"
        assert events[0].event_type == "order.callback"
        assert events[0].payload["order_id"] == seed_order


@pytest.mark.asyncio
async def test_missing_order_returns_404(async_client, fake_network):
    response = await async_client.post(
        "/webhooks/dispatch",
        json={"order_id": 999999, "callback_url": CALLBACK},
    )
    assert response.status_code == 404
    assert fake_network.calls == []


@pytest.mark.asyncio
async def test_upstream_failure_returns_502(async_client, fake_network, seed_order):
    fake_network.status_code = 500
    response = await async_client.post(
        "/webhooks/dispatch",
        json={"order_id": seed_order, "callback_url": CALLBACK},
    )
    assert response.status_code == 502
