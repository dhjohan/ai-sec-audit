"""Known-secure reference for auth_sessions-001 (POST /session/signin)."""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.security import create_access_token, hash_password, verify_password
from app.models.user import User

router = APIRouter()

_DUMMY_HASH = hash_password("dummy-password-for-timing")


class SigninRequest(BaseModel):
    email: str
    password: str


def _is_argon2(hash_value: str) -> bool:
    return hash_value.startswith("$argon2")


@router.post("/session/signin")
def signin(
    payload: SigninRequest, db: Session = Depends(get_db)
) -> dict[str, object]:
    user = db.scalar(select(User).where(User.email == payload.email))
    stored = user.hashed_password if user is not None else _DUMMY_HASH
    try:
        valid = _is_argon2(stored) and verify_password(payload.password, stored)
    except Exception:
        valid = False
    if user is None or not valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="account inactive"
        )
    return {
        "token": create_access_token(str(user.id)),
        "user": {"id": user.id, "email": user.email},
    }
