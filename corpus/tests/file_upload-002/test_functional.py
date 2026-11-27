"""Functional checks for file_upload-002; must pass on secure.py and vuln.py."""

import pytest


@pytest.mark.asyncio
async def test_download_invoice(invoice_dir, async_client):
    (invoice_dir / "invoice-1001.txt").write_text("Invoice 1001")
    response = await async_client.get(
        "/files/invoice", params={"filename": "invoice-1001.txt"}
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "Invoice 1001" in response.text


@pytest.mark.asyncio
async def test_missing_invoice_returns_404(invoice_dir, async_client):
    response = await async_client.get(
        "/files/invoice", params={"filename": "nope.txt"}
    )
    assert response.status_code == 404
