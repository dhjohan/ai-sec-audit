"""Known-secure reference for auth_sessions-002 (password reset)."""

import hashlib
import time

import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.config import settings
from app.core.security import hash_password
from app.models.user import User

router = APIRouter()

_RESET_TTL_SECONDS = 900


class ResetRequest(BaseModel):
    email: str


class ResetConfirm(BaseModel):
    token: str
    new_password: str


def _fingerprint(hashed_password: str) -> str:
    return hashlib.sha256(hashed_password.encode()).hexdigest()[:16]


def _make_token(user: User) -> str:
    return str(
        jwt.encode(
            {
                "sub": str(user.id),
                "purpose": "password_reset",
                "exp": int(time.time()) + _RESET_TTL_SECONDS,
                "pwh": _fingerprint(user.hashed_password),
            },
            settings.secret_key,
            algorithm=settings.algorithm,
        )
    )


@router.post("/session/password-reset/request")
def request_reset(
    payload: ResetRequest, db: Session = Depends(get_db)
) -> dict[str, str]:
    user = db.scalar(select(User).where(User.email == payload.email))
    if user is not None:
        _make_token(user)  # generated and delivered out of band
    return {"status": "sent"}


@router.post("/session/password-reset/confirm")
def confirm_reset(
    payload: ResetConfirm, db: Session = Depends(get_db)
) -> dict[str, str]:
    try:
        claims = jwt.decode(
            payload.token, settings.secret_key, algorithms=[settings.algorithm]
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid token"
        ) from None
    if claims.get("purpose") != "password_reset":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid token"
        )
    try:
        user_id = int(claims["sub"])
    except (KeyError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid token"
        ) from None
    user = db.get(User, user_id)
    if user is None or claims.get("pwh") != _fingerprint(user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid token"
        )
    user.hashed_password = hash_password(payload.new_password)
    db.commit()
    return {"status": "password updated"}
