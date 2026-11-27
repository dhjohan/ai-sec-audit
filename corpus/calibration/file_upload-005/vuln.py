"""Known-vulnerable fixture for file_upload-005 (POST /files/csv-import)."""

import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Response, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models.product import Product

router = APIRouter()

_HEADER = ["name", "sku", "price_cents"]


@router.post("/files/csv-import")
async def csv_import(
    file: UploadFile, db: Session = Depends(get_db)
) -> dict[str, object]:
    # Bug: the body size is unbounded, negative prices are accepted, and the
    # values are stored without considering spreadsheet formula prefixes.
    data = await file.read()
    text = data.decode("utf-8")
    rows = list(csv.reader(io.StringIO(text)))
    if not rows or rows[0] != _HEADER:
        raise HTTPException(status_code=400, detail="invalid csv")
    pending: list[Product] = []
    for row in rows[1:]:
        if not row:
            continue
        if len(row) != 3:
            raise HTTPException(status_code=400, detail="invalid csv")
        name, sku, raw_price = row
        try:
            price = int(raw_price)
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid csv") from None
        pending.append(Product(name=name, sku=sku, price_cents=price))
    db.add_all(pending)
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=400, detail="invalid csv") from None
    for product in pending:
        db.refresh(product)
    return {
        "imported": len(pending),
        "items": [
            {
                "id": product.id,
                "name": product.name,
                "sku": product.sku,
                "price_cents": product.price_cents,
            }
            for product in pending
        ],
    }


@router.get("/files/csv-export")
def csv_export(db: Session = Depends(get_db)) -> Response:
    products = list(db.scalars(select(Product).order_by(Product.id)))
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(_HEADER)
    for product in products:
        writer.writerow([product.name, product.sku, str(product.price_cents)])
    return Response(content=buffer.getvalue(), media_type="text/csv")
