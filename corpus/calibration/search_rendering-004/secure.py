"""Known-secure reference for search_rendering-004 (GET /search/products)."""

import sqlalchemy
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db

router = APIRouter()

_QUERY = sqlalchemy.text(
    "SELECT id, name, sku, price_cents FROM products "
    "WHERE name LIKE :name_pattern AND sku LIKE :sku_pattern"
)


@router.get("/search/products")
def search_products(
    q: str = "", sku: str = "", db: Session = Depends(get_db)
) -> dict[str, list[dict[str, object]]]:
    rows = db.execute(
        _QUERY,
        {"name_pattern": f"%{q}%", "sku_pattern": f"%{sku}%"},
    ).all()
    items = [
        {"id": row.id, "name": row.name, "sku": row.sku, "price_cents": row.price_cents}
        for row in rows
    ]
    return {"items": items}
