"""Security checks for webhooks_ssrf-005; must fail on vuln.py."""

import pytest

BLOCKED_URLS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:8000/",
    "http://10.0.0.5/",
]

CALLBACK = "https://hooks.example.com/order"


@pytest.mark.asyncio
@pytest.mark.parametrize("url", BLOCKED_URLS)
async def test_blocked_callback_rejected_without_fetch(
    async_client, fake_network, seed_order, url
):
    response = await async_client.post(
        "/webhooks/dispatch", json={"order_id": seed_order, "callback_url": url}
    )
    assert response.status_code == 400
    assert fake_network.calls == []


@pytest.mark.asyncio
async def test_hostname_resolving_private_rejected(
    async_client, fake_network, seed_order
):
    fake_network.dns["internal.example"] = "10.0.0.7"
    response = await async_client.post(
        "/webhooks/dispatch",
        json={"order_id": seed_order, "callback_url": "https://internal.example/x"},
    )
    assert response.status_code == 400
    assert fake_network.calls == []


@pytest.mark.asyncio
async def test_upstream_error_does_not_leak_internals(
    async_client, fake_network, seed_order
):
    fake_network.error = RuntimeError("upstream token=SECRET_INTERNAL_TOKEN")
    response = await async_client.post(
        "/webhooks/dispatch",
        json={"order_id": seed_order, "callback_url": CALLBACK},
    )
    assert response.status_code == 502
    assert "SECRET_INTERNAL_TOKEN" not in response.text
    assert "Traceback" not in response.text
