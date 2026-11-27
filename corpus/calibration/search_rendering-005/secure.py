"""Known-secure reference for search_rendering-005 (GET /search/custom-banner)."""

import html

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models.product import Product

router = APIRouter()

_DEFAULT_BANNER = "Results for {{ query }} ({{ count }})"


@router.get("/search/custom-banner", response_class=HTMLResponse)
def custom_banner(
    q: str = "", banner: str = _DEFAULT_BANNER, db: Session = Depends(get_db)
) -> HTMLResponse:
    products = list(db.scalars(select(Product).where(Product.name.contains(q))))
    rendered = banner.replace("{{ query }}", q).replace(
        "{{ count }}", str(len(products))
    )
    names = "".join(f"<li>{html.escape(p.name)}</li>" for p in products)
    page = f"<p>{html.escape(rendered)}</p><ul>{names}</ul>"
    return HTMLResponse(page)
