"""Known-secure reference for webhooks_ssrf-001 (POST /webhooks/stripe)."""

import hashlib
import hmac
import json
import os

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models.webhook_event import WebhookEvent

router = APIRouter()

_SIGNING_KEY = os.environ.get("STRIPE_WEBHOOK_KEY", "whsec_test_secret")


def _expected_signature(raw: bytes) -> str:
    return hmac.new(_SIGNING_KEY.encode(), raw, hashlib.sha256).hexdigest()


@router.post("/webhooks/stripe", status_code=status.HTTP_202_ACCEPTED)
async def stripe_webhook(
    request: Request, db: Session = Depends(get_db)
) -> dict[str, object]:
    raw = await request.body()
    signature = request.headers.get("X-Webhook-Signature")
    if not signature or not hmac.compare_digest(_expected_signature(raw), signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid signature"
        )
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=422, detail="invalid body") from None
    if not isinstance(data, dict):
        raise HTTPException(status_code=422, detail="invalid body")
    event_id = data.get("event_id")
    event_type = data.get("event_type")
    payload = data.get("payload")
    if (
        not isinstance(event_id, str)
        or not isinstance(event_type, str)
        or not isinstance(payload, dict)
    ):
        raise HTTPException(status_code=422, detail="invalid body")
    event = WebhookEvent(
        source="stripe",
        event_type=event_type,
        payload={**payload, "event_id": event_id},
        processed=True,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return {"status": "accepted", "event_id": event_id, "webhook_id": event.id}
