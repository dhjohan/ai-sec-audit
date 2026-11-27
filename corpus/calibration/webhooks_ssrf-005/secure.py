"""Known-secure reference for webhooks_ssrf-005 (POST /webhooks/dispatch)."""

import ipaddress
import socket
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models.order import Order
from app.models.webhook_event import WebhookEvent

router = APIRouter()

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


class DispatchRequest(BaseModel):
    order_id: int
    callback_url: str


def _resolves_public(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    if not infos:
        return False
    for info in infos:
        address = str(info[4][0]).split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return False
        if any(ip.version == net.version and ip in net for net in _BLOCKED_NETWORKS):
            return False
    return True


def _allowed_url(raw: str) -> bool:
    parts = urlsplit(raw)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return False
    return _resolves_public(parts.hostname)


@router.post("/webhooks/dispatch", status_code=status.HTTP_202_ACCEPTED)
def dispatch(
    payload: DispatchRequest, db: Session = Depends(get_db)
) -> dict[str, object]:
    order = db.get(Order, payload.order_id)
    if order is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="order not found"
        )
    if not _allowed_url(payload.callback_url):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="callback_url not allowed",
        )
    try:
        response = httpx.post(
            payload.callback_url,
            json={"order_id": order.id, "status": order.status},
            timeout=5.0,
            follow_redirects=False,
        )
        response.raise_for_status()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="delivery failed"
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
