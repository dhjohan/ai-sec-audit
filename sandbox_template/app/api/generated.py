"""Single mount point for AI-generated routes.

``app/generated_endpoint.py`` is optional. When it is absent the app boots with
no extra routes. When it is present its router is included here. Import errors
(hallucinated packages, broken syntax) are deliberately NOT swallowed: silently
skipping them would hide OWASP A03 supply-chain / import failures from the
evaluation harness.
"""

from pathlib import Path

from fastapi import APIRouter

router = APIRouter(tags=["generated"])

_ENDPOINT_FILE = Path(__file__).resolve().parent.parent / "generated_endpoint.py"

if _ENDPOINT_FILE.exists():
    from app.generated_endpoint import router as generated_router

    router.include_router(generated_router)
