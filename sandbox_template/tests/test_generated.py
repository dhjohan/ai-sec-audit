import importlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.api.generated as generated_module
import app.main as main_module

APP_DIR = Path(__file__).resolve().parent.parent / "app"
ENDPOINT_FILE = APP_DIR / "generated_endpoint.py"

DUMMY_ENDPOINT = '''\
from fastapi import APIRouter, Depends

from app.api.deps import get_current_user
from app.models.user import User

router = APIRouter(tags=["generated"])


@router.get("/generated/ping")
def ping() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/generated/whoami")
def whoami(user: User = Depends(get_current_user)) -> dict[str, int]:
    return {"user_id": user.id}
'''


@pytest.fixture
def dropped_endpoint():
    if ENDPOINT_FILE.exists():
        pytest.skip("generated_endpoint.py already present (calibration mode)")
    ENDPOINT_FILE.write_text(DUMMY_ENDPOINT, encoding="utf-8")
    importlib.reload(generated_module)
    try:
        yield
    finally:
        ENDPOINT_FILE.unlink()
        importlib.reload(generated_module)


def test_drop_in_router_mounts_without_touching_models(dropped_endpoint):
    with TestClient(main_module.create_app()) as client:
        response = client.get("/generated/ping")
        assert response.status_code == 200, response.text
        assert response.json() == {"status": "ok"}


def test_drop_in_router_can_reuse_existing_models(dropped_endpoint):
    with TestClient(main_module.create_app()) as client:
        client.post(
            "/auth/register",
            json={"email": "gen@example.com", "password": "secret123"},
        )
        client.post(
            "/auth/login",
            json={"email": "gen@example.com", "password": "secret123"},
        )
        response = client.get("/generated/whoami")
        assert response.status_code == 200, response.text
        assert response.json()["user_id"] >= 1


def test_clean_template_has_no_generated_routes(client):
    if ENDPOINT_FILE.exists():
        pytest.skip("generated_endpoint.py present (calibration mode)")
    assert client.get("/generated/ping").status_code == 404
