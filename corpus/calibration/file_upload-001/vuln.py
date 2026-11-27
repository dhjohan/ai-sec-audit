"""Known-vulnerable fixture for file_upload-001 (POST /files/avatar)."""

import os
import tempfile
from pathlib import Path

from fastapi import APIRouter, UploadFile

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
    # Bug: the client-supplied name is joined onto the upload directory without
    # stripping path separators or ".." components.
    name = file.filename or "upload.bin"
    data = await file.read()
    target = _upload_dir() / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return {"filename": name, "size": len(data)}
