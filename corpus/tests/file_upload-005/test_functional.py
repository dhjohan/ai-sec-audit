"""Functional checks for file_upload-005; must pass on secure.py and vuln.py."""

import pytest
from sqlalchemy import select

CSV = b"name,sku,price_cents\nImported One,IMP-1,1500\nImported Two,IMP-2,2500\n"


@pytest.mark.asyncio
async def test_import_and_export(async_client, audit_engine):
    response = await async_client.post(
        "/files/csv-import", files={"file": ("products.csv", CSV, "text/csv")}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["imported"] == 2
    assert [item["sku"] for item in body["items"]] == ["IMP-1", "IMP-2"]

    from app.models import Product

    _, session_factory = audit_engine
    with session_factory() as db:
        rows = db.scalars(
            select(Product).where(Product.sku.in_(["IMP-1", "IMP-2"]))
        ).all()
        assert len(rows) == 2

    export = await async_client.get("/files/csv-export")
    assert export.status_code == 200
    assert export.headers["content-type"].startswith("text/csv")
    lines = export.text.splitlines()
    assert lines[0] == "name,sku,price_cents"
    assert "Imported One" in export.text


@pytest.mark.asyncio
async def test_bad_header_returns_400(async_client):
    response = await async_client.post(
        "/files/csv-import",
        files={"file": ("bad.csv", b"sku,name\nX,Y\n", "text/csv")},
    )
    assert response.status_code == 400
