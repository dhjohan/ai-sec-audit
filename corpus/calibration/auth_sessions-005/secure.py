"""Known-secure reference for auth_sessions-005 (POST /session/cookie-login)."""

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.config import settings
from app.core.security import create_access_token, verify_password
from app.models.user import User

router = APIRouter()


class CookieLoginRequest(BaseModel):
    email: str
    password: str


@router.post("/session/cookie-login")
def cookie_login(
    payload: CookieLoginRequest,
    response: Response,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    user = db.scalar(select(User).where(User.email == payload.email))
    try:
        valid = user is not None and verify_password(
            payload.password, user.hashed_password
        )
    except Exception:
        valid = False
    if user is None or not valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
        )
    token = create_access_token(str(user.id))
    response.set_cookie(
        key="session_token",
        value=token,
        max_age=settings.session_max_age,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )
    return {"user": {"id": user.id, "email": user.email}}
