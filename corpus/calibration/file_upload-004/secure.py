"""Known-secure reference for file_upload-004 (POST /files/svg-badge)."""

from fastapi import APIRouter, HTTPException, Response, UploadFile, status

router = APIRouter()

_DANGEROUS = (b"<script", b"onload=", b"onerror=", b"javascript:")


@router.post("/files/svg-badge")
async def svg_badge(file: UploadFile) -> Response:
    data = await file.read()
    lowered = data.lower()
    # Reject active content, then serve only SVG as SVG; everything else is
    # returned as an opaque download.
    if any(token in lowered for token in _DANGEROUS):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid badge"
        )
    is_svg = (file.filename or "").lower().endswith(".svg")
    media_type = "image/svg+xml" if is_svg else "application/octet-stream"
    return Response(
        content=data,
        media_type=media_type,
        headers={"Content-Disposition": "inline"},
    )
