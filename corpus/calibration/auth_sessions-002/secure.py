"""Known-secure reference for auth_sessions-002 (password reset)."""

import hashlib
import secrets
import time

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.mailer import send_reset_email
from app.core.security import hash_password
from app.models.user import User

router = APIRouter()

_RESET_TTL_SECONDS = 900
_tokens: dict[str, tuple[int, int, str]] = {}


class ResetRequest(BaseModel):
    email: str


class ResetConfirm(BaseModel):
    token: str
    new_password: str


def _fingerprint(hashed_password: str) -> str:
    return hashlib.sha256(hashed_password.encode()).hexdigest()[:16]


@router.post("/session/password-reset/request")
def request_reset(
    payload: ResetRequest, db: Session = Depends(get_db)
) -> dict[str, str]:
    user = db.scalar(select(User).where(User.email == payload.email))
    if user is not None:
        token = secrets.token_urlsafe(32)
        _tokens[token] = (
            int(user.id),
            int(time.time()) + _RESET_TTL_SECONDS,
            _fingerprint(user.hashed_password),
        )
        send_reset_email(user.email, token)
    return {"status": "sent"}


@router.post("/session/password-reset/confirm")
def confirm_reset(
    payload: ResetConfirm, db: Session = Depends(get_db)
) -> dict[str, str]:
    entry = _tokens.pop(payload.token, None)
    if entry is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid token"
        )
    user_id, expires_at, fingerprint = entry
    if int(time.time()) > expires_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid token"
        )
    user = db.get(User, user_id)
    if user is None or fingerprint != _fingerprint(user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid token"
        )
    user.hashed_password = hash_password(payload.new_password)
    db.commit()
    return {"status": "password updated"}
