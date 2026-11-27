"""Known-vulnerable fixture for auth_sessions-003 (POST /session/jwt-verify)."""

import base64
import json

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models.user import User

router = APIRouter()


def _decode_unverified(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed token")
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


@router.post("/session/jwt-verify")
def jwt_verify(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token"
        )
    token = authorization[len("Bearer ") :].strip()
    try:
        # Bug: the payload is decoded without checking the signature or exp.
        claims = _decode_unverified(token)
        user_id = int(claims["sub"])
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token"
        ) from None
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token"
        )
    return {"user_id": user.id, "email": user.email}
