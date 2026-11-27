"""Functional checks for file_upload-004; must pass on secure.py and vuln.py."""

import pytest

BENIGN_SVG = b'<svg xmlns="http://www.w3.org/2000/svg"><circle r="5"/></svg>'


@pytest.mark.asyncio
async def test_benign_svg_returned_inline(async_client):
    response = await async_client.post(
        "/files/svg-badge",
        files={"file": ("badge.svg", BENIGN_SVG, "image/svg+xml")},
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/svg+xml")
    assert response.content == BENIGN_SVG


@pytest.mark.asyncio
async def test_missing_file_returns_422(async_client):
    response = await async_client.post("/files/svg-badge")
    assert response.status_code == 422
