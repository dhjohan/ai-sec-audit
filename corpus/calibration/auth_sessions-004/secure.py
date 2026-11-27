"""Known-secure reference for auth_sessions-004 (POST /session/mfa-verify)."""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models.audit_log import AuditLog

router = APIRouter()

_MAX_FAILURES = 5
_failures: dict[str, int] = {}


class MfaRequest(BaseModel):
    email: str
    code: str


@router.post("/session/mfa-verify")
def mfa_verify(
    payload: MfaRequest, db: Session = Depends(get_db)
) -> dict[str, bool]:
    if _failures.get(payload.email, 0) >= _MAX_FAILURES:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too many attempts",
        )
    record = db.scalars(
        select(AuditLog)
        .where(AuditLog.action == "otp", AuditLog.resource == payload.email)
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
    ).first()
    expected = record.detail if record is not None else None
    if expected is None or payload.code != expected:
        _failures[payload.email] = _failures.get(payload.email, 0) + 1
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid code"
        )
    _failures.pop(payload.email, None)
    return {"verified": True}
