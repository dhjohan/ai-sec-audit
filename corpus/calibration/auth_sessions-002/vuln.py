"""Known-vulnerable fixture for auth_sessions-002 (password reset)."""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.mailer import send_reset_email
from app.core.security import hash_password
from app.models.user import User

router = APIRouter()

_tokens: dict[str, int] = {}
_next_token = 1000


class ResetRequest(BaseModel):
    email: str


class ResetConfirm(BaseModel):
    token: str
    new_password: str


@router.post("/session/password-reset/request")
def request_reset(
    payload: ResetRequest, db: Session = Depends(get_db)
) -> dict[str, object]:
    global _next_token
    user = db.scalar(select(User).where(User.email == payload.email))
    if user is None:
        # Bug: unknown emails are distinguishable.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="user not found"
        )
    _next_token += 1
    token = str(_next_token)
    _tokens[token] = int(user.id)
    send_reset_email(user.email, token)
    # Bug: the token is also returned in the response.
    return {"status": "sent", "token": token}


@router.post("/session/password-reset/confirm")
def confirm_reset(
    payload: ResetConfirm, db: Session = Depends(get_db)
) -> dict[str, str]:
    user_id = _tokens.get(payload.token)
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid token"
        )
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid token"
        )
    # Bug: the token is never consumed.
    user.hashed_password = hash_password(payload.new_password)
    db.commit()
    return {"status": "password updated"}
