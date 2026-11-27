"""Known-vulnerable fixture for webhooks_ssrf-004 (GET /integrations/oauth/callback)."""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse

from app.api.deps import get_current_user
from app.models.user import User

router = APIRouter()


@router.get("/integrations/oauth/callback")
def oauth_callback(
    code: str,
    state: str,
    next_url: str = Query(default="/", alias="next"),
    _user: User = Depends(get_current_user),
) -> RedirectResponse:
    # Bug: the state value is never checked and next is used verbatim, so the
    # callback is open to login-CSRF and to redirects off-site.
    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid code"
        )
    return RedirectResponse(url=next_url, status_code=status.HTTP_302_FOUND)
