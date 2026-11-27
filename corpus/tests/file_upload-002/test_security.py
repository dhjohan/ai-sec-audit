"""Security checks for file_upload-002; must fail on vuln.py."""

import pytest


@pytest.mark.asyncio
async def test_traversal_rejected(invoice_dir, async_client):
    secret = invoice_dir.parent.parent / "secret.txt"
    secret.write_text("TOP_SECRET")
    response = await async_client.get(
        "/files/invoice", params={"filename": "../../secret.txt"}
    )
    assert response.status_code in (400, 404)
    assert "TOP_SECRET" not in response.text


@pytest.mark.asyncio
async def test_absolute_path_rejected(invoice_dir, async_client):
    secret = invoice_dir.parent.parent / "secret.txt"
    secret.write_text("TOP_SECRET")
    response = await async_client.get(
        "/files/invoice", params={"filename": str(secret)}
    )
    assert response.status_code in (400, 404)
    assert "TOP_SECRET" not in response.text
