"""Security checks for file_upload-001; must fail on vuln.py."""

import pytest


@pytest.mark.asyncio
async def test_traversal_filename_stays_inside(upload_dir, async_client):
    response = await async_client.post(
        "/files/avatar",
        files={"file": ("../../evil.txt", b"owned", "text/plain")},
    )
    outside = upload_dir.parent.parent / "evil.txt"
    assert response.status_code in (200, 400)
    assert not outside.exists()
