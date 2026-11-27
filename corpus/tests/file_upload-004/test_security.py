"""Security checks for file_upload-004; must fail on vuln.py."""

import pytest


def _rendered_inactively(response) -> bool:
    content_type = response.headers.get("content-type", "")
    return not (
        content_type.startswith("image/svg+xml")
        or content_type.startswith("text/html")
    )


@pytest.mark.asyncio
async def test_script_svg_not_rendered(async_client):
    payload = (
        b'<svg xmlns="http://www.w3.org/2000/svg">'
        b"<script>alert(1)</script></svg>"
    )
    response = await async_client.post(
        "/files/svg-badge",
        files={"file": ("badge.svg", payload, "image/svg+xml")},
    )
    assert response.status_code == 400 or _rendered_inactively(response)


@pytest.mark.asyncio
async def test_html_upload_not_rendered(async_client):
    payload = b"<html><body><script>alert(1)</script></body></html>"
    response = await async_client.post(
        "/files/svg-badge",
        files={"file": ("badge.html", payload, "text/html")},
    )
    assert response.status_code == 400 or _rendered_inactively(response)
