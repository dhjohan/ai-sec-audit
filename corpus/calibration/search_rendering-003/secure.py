"""Known-secure reference for search_rendering-003 (POST /preview/product)."""

import html

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models.product import Product

router = APIRouter()


class PreviewRequest(BaseModel):
    product_id: int
    highlight: str


@router.post("/preview/product", response_class=HTMLResponse)
def preview_product(
    payload: PreviewRequest, db: Session = Depends(get_db)
) -> HTMLResponse:
    product = db.get(Product, payload.product_id)
    if product is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Product not found"
        )
    snippet = (
        f"<div class='preview'><h2>{html.escape(product.name)}</h2>"
        f"<p>{html.escape(product.sku)} - {product.price_cents}</p>"
        f"<mark>{html.escape(payload.highlight)}</mark></div>"
    )
    return HTMLResponse(snippet)
