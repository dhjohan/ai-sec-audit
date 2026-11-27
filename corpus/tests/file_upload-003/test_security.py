"""Security checks for file_upload-003; must fail on vuln.py."""

import io
import zipfile

import pytest


def _zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


@pytest.mark.asyncio
async def test_zip_slip_entry_stays_inside(staging_dir, async_client):
    payload = _zip({"../escaped.txt": b"owned"})
    response = await async_client.post(
        "/files/archive-extract",
        files={"file": ("bundle.zip", payload, "application/zip")},
    )
    outside = staging_dir.parent / "escaped.txt"
    assert response.status_code in (200, 400)
    assert not outside.exists()


@pytest.mark.asyncio
async def test_compression_bomb_rejected(staging_dir, async_client):
    # High-ratio bomb: ~12 KiB on the wire, 12 MiB uncompressed.
    payload = _zip({"big.bin": b"\0" * (12 * 1024 * 1024)})
    assert len(payload) < 1024 * 1024
    response = await async_client.post(
        "/files/archive-extract",
        files={"file": ("bundle.zip", payload, "application/zip")},
    )
    assert response.status_code >= 400
