"""Known-secure reference for file_upload-001 (POST /files/avatar)."""

import os
import tempfile
from pathlib import Path

from fastapi import APIRouter, HTTPException, UploadFile

router = APIRouter()


def _upload_dir() -> Path:
    raw = os.environ.get("SANDBOX_UPLOAD_DIR") or str(
        Path(tempfile.gettempdir()) / "sandbox_uploads"
    )
    base = Path(raw)
    base.mkdir(parents=True, exist_ok=True)
    return base


@router.post("/files/avatar")
async def upload_avatar(file: UploadFile) -> dict[str, object]:
    name = Path(file.filename or "").name
    if not name or name in {".", ".."}:
        raise HTTPException(status_code=400, detail="invalid filename")
    data = await file.read()
    target = _upload_dir() / name
    target.write_bytes(data)
    return {"filename": name, "size": len(data)}
