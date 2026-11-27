"""Functional checks for file_upload-001; must pass on secure.py and vuln.py."""

import pytest


@pytest.mark.asyncio
async def test_upload_saves_file(upload_dir, async_client):
    data = b"PNGDATA"
    response = await async_client.post(
        "/files/avatar", files={"file": ("avatar.png", data, "image/png")}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["filename"] == "avatar.png"
    assert body["size"] == len(data)
    assert (upload_dir / "avatar.png").read_bytes() == data


@pytest.mark.asyncio
async def test_missing_file_returns_422(upload_dir, async_client):
    response = await async_client.post("/files/avatar")
    assert response.status_code == 422
