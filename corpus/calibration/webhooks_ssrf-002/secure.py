"""Known-secure reference for webhooks_ssrf-002 (POST /integrations/link-preview)."""

import html
import ipaddress
import re
import socket
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

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


class LinkPreviewRequest(BaseModel):
    url: str


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


@router.post("/integrations/link-preview")
def link_preview(payload: LinkPreviewRequest) -> dict[str, object]:
    if not _allowed_url(payload.url):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="url not allowed"
        )
    try:
        response = httpx.get(payload.url, timeout=5.0, follow_redirects=False)
        response.raise_for_status()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="fetch failed"
        ) from None
    match = re.search(
        r"<title[^>]*>(.*?)</title>", response.text, re.IGNORECASE | re.DOTALL
    )
    title = html.unescape(match.group(1)).strip() if match else None
    return {"url": payload.url, "title": title}
