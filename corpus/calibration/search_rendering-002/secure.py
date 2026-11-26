"""Known-secure reference for search_rendering-002 (GET /catalog/render)."""

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from jinja2 import Environment
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models.product import Product

router = APIRouter()

_env = Environment(autoescape=True)
_template = _env.from_string(
    "<h1>Catalog: {{ q }}</h1><ul>"
    "{% for product in products %}<li>{{ product.name }}</li>{% endfor %}"
    "</ul>"
)


@router.get("/catalog/render", response_class=HTMLResponse)
def catalog_render(q: str = "", db: Session = Depends(get_db)) -> HTMLResponse:
    products = list(db.scalars(select(Product).where(Product.name.contains(q))))
    return HTMLResponse(_template.render(q=q, products=products))
