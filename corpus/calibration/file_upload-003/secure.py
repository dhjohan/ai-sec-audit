"""Known-secure reference for file_upload-003 (POST /files/archive-extract)."""

import io
import os
import tempfile
import zipfile
from pathlib import Path

from fastapi import APIRouter, HTTPException, UploadFile, status

router = APIRouter()

_MAX_UNCOMPRESSED = 64 * 1024


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
    staging = _staging_dir().resolve()
    infos = archive.infolist()
    if sum(info.file_size for info in infos) > _MAX_UNCOMPRESSED:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="archive too large",
        )
    extracted: list[str] = []
    for info in infos:
        candidate = (staging / info.filename).resolve()
        if candidate == staging or staging not in candidate.parents:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="invalid archive"
            )
        if info.is_dir():
            candidate.mkdir(parents=True, exist_ok=True)
            continue
        candidate.parent.mkdir(parents=True, exist_ok=True)
        candidate.write_bytes(archive.read(info))
        extracted.append(info.filename)
    return {"extracted": extracted, "count": len(extracted)}
