"""Known-secure reference for file_upload-002 (GET /files/invoice)."""

import os
import tempfile
from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse

router = APIRouter()


def _invoice_dir() -> Path:
    raw = os.environ.get("SANDBOX_INVOICE_DIR") or str(
        Path(tempfile.gettempdir()) / "invoices"
    )
    base = Path(raw)
    base.mkdir(parents=True, exist_ok=True)
    return base


@router.get("/files/invoice")
def download_invoice(filename: str) -> FileResponse:
    name = Path(filename).name
    if not name or name != filename or Path(filename).is_absolute():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid filename"
        )
    target = _invoice_dir() / name
    if not target.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="invoice not found"
        )
    return FileResponse(target, media_type="text/plain")
