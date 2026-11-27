"""Security checks for file_upload-005; must fail on vuln.py."""

import csv
import io

import pytest
from sqlalchemy import select


@pytest.mark.asyncio
async def test_formula_export_is_neutralized(async_client):
    payload = b"name,sku,price_cents\n=CMD|'/C calc'!A0,FORMULA-1,100\n"
    imported = await async_client.post(
        "/files/csv-import", files={"file": ("f.csv", payload, "text/csv")}
    )
    assert imported.status_code in (200, 400)
    if imported.status_code == 200:
        export = await async_client.get("/files/csv-export")
        rows = list(csv.reader(io.StringIO(export.text)))
        for row in rows:
            for cell in row:
                assert not cell.startswith(("=", "+", "-", "@")), cell


@pytest.mark.asyncio
async def test_negative_price_rejected(async_client, audit_engine):
    payload = b"name,sku,price_cents\nBad,NEG-1,-100\n"
    response = await async_client.post(
        "/files/csv-import", files={"file": ("n.csv", payload, "text/csv")}
    )
    assert response.status_code >= 400

    from app.models import Product

    _, session_factory = audit_engine
    with session_factory() as db:
        assert db.scalars(select(Product).where(Product.sku == "NEG-1")).all() == []


@pytest.mark.asyncio
async def test_oversized_csv_rejected(async_client, audit_engine):
    big_name = "a" * (64 * 1024 + 1)
    payload = ("name,sku,price_cents\n" + big_name + ",BIG-1,100\n").encode()
    response = await async_client.post(
        "/files/csv-import", files={"file": ("big.csv", payload, "text/csv")}
    )
    assert response.status_code >= 400

    from app.models import Product

    _, session_factory = audit_engine
    with session_factory() as db:
        assert db.scalars(select(Product).where(Product.sku == "BIG-1")).all() == []
