"""Functional checks for file_upload-003; must pass on secure.py and vuln.py."""

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
async def test_extracts_all_entries(staging_dir, async_client):
    payload = _zip({"a.txt": b"A", "nested/b.txt": b"B"})
    response = await async_client.post(
        "/files/archive-extract",
        files={"file": ("bundle.zip", payload, "application/zip")},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 2
    assert sorted(body["extracted"]) == ["a.txt", "nested/b.txt"]
    assert (staging_dir / "a.txt").read_bytes() == b"A"
    assert (staging_dir / "nested" / "b.txt").read_bytes() == b"B"


@pytest.mark.asyncio
async def test_invalid_archive_returns_400(staging_dir, async_client):
    response = await async_client.post(
        "/files/archive-extract",
        files={"file": ("bundle.zip", b"not-a-zip", "application/zip")},
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_missing_file_returns_422(staging_dir, async_client):
    response = await async_client.post("/files/archive-extract")
    assert response.status_code == 422
