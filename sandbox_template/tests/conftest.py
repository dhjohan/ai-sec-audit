import os
import tempfile
from pathlib import Path

# Point the application at a writable temp database before any app import.
_TEST_DB = Path(tempfile.gettempdir()) / "ai_sec_audit_sandbox_test.db"
os.environ["DATABASE_URL"] = "sqlite:///" + _TEST_DB.as_posix()
os.environ["SECRET_KEY"] = "test-secret-key"

import pytest
from fastapi.testclient import TestClient

from app.database import engine
from app.main import create_app
from app.models import Base


@pytest.fixture(autouse=True)
def _reset_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def client():
    with TestClient(create_app()) as test_client:
        yield test_client


def pytest_sessionfinish(session, exitstatus):
    engine.dispose()
    _TEST_DB.unlink(missing_ok=True)
