"""Known-vulnerable fixture for auth_sessions-004 (POST /session/mfa-verify)."""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models.audit_log import AuditLog

router = APIRouter()


class MfaRequest(BaseModel):
    email: str
    code: str


@router.post("/session/mfa-verify")
def mfa_verify(
    payload: MfaRequest, db: Session = Depends(get_db)
) -> dict[str, bool]:
    # Bug: there is no limit on consecutive failed attempts.
    record = db.scalars(
        select(AuditLog)
        .where(AuditLog.action == "otp", AuditLog.resource == payload.email)
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
    ).first()
    expected = record.detail if record is not None else None
    if expected is None or payload.code != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid code"
        )
    return {"verified": True}
