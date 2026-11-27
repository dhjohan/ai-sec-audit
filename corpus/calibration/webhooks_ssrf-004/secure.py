"""Known-secure reference for webhooks_ssrf-004 (GET /integrations/oauth/callback)."""

from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse

from app.api.deps import get_current_user
from app.models.user import User

router = APIRouter()


def _safe_next(next_url: str) -> bool:
    if not next_url.startswith("/") or next_url.startswith("//"):
        return False
    if "\\" in next_url:
        return False
    parts = urlsplit(next_url)
    return not parts.scheme and not parts.netloc


@router.get("/integrations/oauth/callback")
def oauth_callback(
    code: str,
    state: str,
    next_url: str = Query(default="/", alias="next"),
    user: User = Depends(get_current_user),
) -> RedirectResponse:
    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid code"
        )
    if state != f"state-{user.id}":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid state"
        )
    if not _safe_next(next_url):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid next"
        )
    return RedirectResponse(url=next_url, status_code=status.HTTP_302_FOUND)
