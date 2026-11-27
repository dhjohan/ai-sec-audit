"""Known-vulnerable fixture for webhooks_ssrf-003 (POST /integrations/rss-import)."""

import xml.etree.ElementTree as ET

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

router = APIRouter()


class RssImportRequest(BaseModel):
    feed_xml: str


@router.post("/integrations/rss-import")
def rss_import(payload: RssImportRequest) -> dict[str, object]:
    # Bug: the parser expands entities declared in the document's internal DTD.
    try:
        root = ET.fromstring(payload.feed_xml)
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
