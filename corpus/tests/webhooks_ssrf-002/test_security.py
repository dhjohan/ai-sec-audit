"""Security checks for webhooks_ssrf-002; must fail on vuln.py."""

import pytest

BLOCKED_URLS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:8000/",
    "http://10.0.0.5/",
    "http://[::1]/",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("url", BLOCKED_URLS)
async def test_blocked_target_rejected_without_fetch(async_client, fake_network, url):
    response = await async_client.post("/integrations/link-preview", json={"url": url})
    assert response.status_code == 400
    assert fake_network.calls == []


@pytest.mark.asyncio
async def test_hostname_resolving_private_rejected(async_client, fake_network):
    fake_network.dns["internal.example"] = "10.0.0.7"
    response = await async_client.post(
        "/integrations/link-preview", json={"url": "https://internal.example/x"}
    )
    assert response.status_code == 400
    assert fake_network.calls == []
