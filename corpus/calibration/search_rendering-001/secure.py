"""Known-secure reference for search_rendering-001 (GET /search/html)."""

import html

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
    rows = "".join(
        f"<li>{html.escape(p.name)} / {html.escape(p.sku)}</li>" for p in products
    )
    page = f"<h1>Results for {html.escape(q)}</h1><ul>{rows}</ul>"
    return HTMLResponse(page)
