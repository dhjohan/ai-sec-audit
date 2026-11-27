"""Known-vulnerable fixture for webhooks_ssrf-002 (POST /integrations/link-preview)."""

import html
import re
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

router = APIRouter()


class LinkPreviewRequest(BaseModel):
    url: str


@router.post("/integrations/link-preview")
def link_preview(payload: LinkPreviewRequest) -> dict[str, object]:
    # Bug: only the scheme is checked; the resolved address is never inspected,
    # so loopback, link-local and metadata targets are fetched directly.
    parts = urlsplit(payload.url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="url not allowed"
        )
    try:
        response = httpx.get(payload.url, timeout=5.0, follow_redirects=True)
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
