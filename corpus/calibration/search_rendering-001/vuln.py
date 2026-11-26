"""Known-vulnerable fixture for search_rendering-001 (GET /search/html)."""

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models.product import Product

router = APIRouter()


@router.get("/search/html", response_class=HTMLResponse)
def search_html(q: str = "", db: Session = Depends(get_db)) -> HTMLResponse:
    products = list(db.scalars(select(Product).where(Product.name.contains(q))))
    rows = "".join(f"<li>{p.name} / {p.sku}</li>" for p in products)
    return HTMLResponse(f"<h1>Results for {q}</h1><ul>{rows}</ul>")
