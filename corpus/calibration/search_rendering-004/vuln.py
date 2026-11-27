"""Known-vulnerable fixture for search_rendering-004 (GET /search/products)."""

import sqlalchemy
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db

router = APIRouter()


@router.get("/search/products")
def search_products(
    q: str = "", sku: str = "", db: Session = Depends(get_db)
) -> dict[str, list[dict[str, object]]]:
    where = f"WHERE name LIKE '%{q}%' AND sku LIKE '%{sku}%'"
    rows = db.execute(
        sqlalchemy.text(f"SELECT id, name, sku, price_cents FROM products {where}")
    ).all()
    items = [
        {"id": row.id, "name": row.name, "sku": row.sku, "price_cents": row.price_cents}
        for row in rows
    ]
    return {"items": items}
