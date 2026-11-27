"""Known-vulnerable fixture for file_upload-004 (POST /files/svg-badge)."""

import mimetypes

from fastapi import APIRouter, Response, UploadFile

router = APIRouter()


@router.post("/files/svg-badge")
async def svg_badge(file: UploadFile) -> Response:
    # Bug: the uploaded bytes are echoed with the client-declared content type,
    # so an SVG (or HTML) document containing script is rendered inline.
    data = await file.read()
    media_type = (
        file.content_type
        or mimetypes.guess_type(file.filename or "")[0]
        or "application/octet-stream"
    )
    return Response(
        content=data,
        media_type=media_type,
        headers={"Content-Disposition": "inline"},
    )
