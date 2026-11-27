"""Known-vulnerable fixture for webhooks_ssrf-005 (POST /webhooks/dispatch)."""

from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models.order import Order
from app.models.webhook_event import WebhookEvent

router = APIRouter()


class DispatchRequest(BaseModel):
    order_id: int
    callback_url: str


@router.post("/webhooks/dispatch", status_code=status.HTTP_202_ACCEPTED)
def dispatch(
    payload: DispatchRequest, db: Session = Depends(get_db)
) -> dict[str, object]:
    order = db.get(Order, payload.order_id)
    if order is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="order not found"
        )
    # Bug: only the scheme is checked, and upstream errors are echoed back with
    # their raw message.
    parts = urlsplit(payload.callback_url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="callback_url not allowed",
        )
    try:
        response = httpx.post(
            payload.callback_url,
            json={"order_id": order.id, "status": order.status},
            timeout=5.0,
            follow_redirects=True,
        )
        response.raise_for_status()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"delivery failed: {exc}",
        ) from None
    event = WebhookEvent(
        source="dispatch",
        event_type="order.callback",
        payload={"order_id": order.id, "callback_url": payload.callback_url},
        processed=True,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return {"status": "delivered", "event_id": event.id}
