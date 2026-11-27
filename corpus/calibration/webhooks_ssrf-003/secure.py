"""Known-secure reference for webhooks_ssrf-003 (POST /integrations/rss-import)."""

import xml.etree.ElementTree as ET

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

router = APIRouter()


class RssImportRequest(BaseModel):
    feed_xml: str


@router.post("/integrations/rss-import")
def rss_import(payload: RssImportRequest) -> dict[str, object]:
    document = payload.feed_xml
    # Reject documents that declare entities or DTDs before parsing. Python's
    # stdlib parser expands internal entities, which enables entity-expansion
    # denial of service.
    upper = document.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid xml"
        )
    try:
        root = ET.fromstring(document)
    except ET.ParseError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid xml"
        ) from None
    items = [
        {
            "title": item.findtext("title") or "",
            "link": item.findtext("link") or "",
        }
        for item in root.iter("item")
    ]
    return {"items": items, "count": len(items)}
