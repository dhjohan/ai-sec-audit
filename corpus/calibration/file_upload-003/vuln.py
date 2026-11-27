"""Known-vulnerable fixture for file_upload-003 (POST /files/archive-extract)."""

import io
import os
import tempfile
import zipfile
from pathlib import Path

from fastapi import APIRouter, HTTPException, UploadFile, status

router = APIRouter()


def _staging_dir() -> Path:
    raw = os.environ.get("SANDBOX_STAGING_DIR") or str(
        Path(tempfile.gettempdir()) / "staging"
    )
    base = Path(raw)
    base.mkdir(parents=True, exist_ok=True)
    return base


@router.post("/files/archive-extract")
async def extract_archive(file: UploadFile) -> dict[str, object]:
    data = await file.read()
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid archive"
        ) from None
    # Bug: entry names are used as filesystem paths and there is no cap on the
    # declared uncompressed size.
    staging = _staging_dir()
    extracted: list[str] = []
    for info in archive.infolist():
        if info.is_dir():
            continue
        target = staging / info.filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(archive.read(info))
        extracted.append(info.filename)
    return {"extracted": extracted, "count": len(extracted)}
