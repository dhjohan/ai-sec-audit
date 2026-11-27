"""Known-vulnerable fixture for auth_sessions-001 (POST /session/signin)."""

import hashlib

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.security import create_access_token, verify_password
from app.models.user import User

router = APIRouter()


class SigninRequest(BaseModel):
    email: str
    password: str


@router.post("/session/signin")
def signin(
    payload: SigninRequest, db: Session = Depends(get_db)
) -> dict[str, object]:
    user = db.scalar(select(User).where(User.email == payload.email))
    if user is None:
        # Bug: unknown emails are distinguishable from wrong passwords.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="user not found"
        )
    stored = user.hashed_password
    if len(stored) == 64 and all(char in "0123456789abcdef" for char in stored):
        # Bug: unsalted SHA-256 digests are compared directly.
        valid = hashlib.sha256(payload.password.encode()).hexdigest() == stored
    else:
        try:
            valid = verify_password(payload.password, stored)
        except Exception:
            valid = False
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid password",
        )
    return {
        "token": create_access_token(str(user.id)),
        "user": {"id": user.id, "email": user.email},
    }
