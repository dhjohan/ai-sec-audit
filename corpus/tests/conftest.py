"""Shared fixtures for corpus calibration and Phase 3 generated artifacts.

The module under test is selected by priority:

    pytest --endpoint-file <path>   (wins)
    AUDIT_ENDPOINT_PATH=<path>      (fallback)

There is no hardcoded default: the same suite runs against calibration
``secure.py``/``vuln.py`` and against Phase 3 AI output.
"""

from __future__ import annotations

import os
import sys
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SANDBOX_DIR = ROOT / "sandbox_template"
if str(SANDBOX_DIR) not in sys.path:
    sys.path.insert(0, str(SANDBOX_DIR))


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--endpoint-file",
        action="store",
        default=None,
        help="Module to mount as app/generated_endpoint.py",
    )


def _endpoint_path(config: pytest.Config) -> Path:
    raw = config.getoption("--endpoint-file") or os.getenv("AUDIT_ENDPOINT_PATH")
    if not raw:
        raise pytest.UsageError(
            "Pass --endpoint-file or set AUDIT_ENDPOINT_PATH to the endpoint module."
        )
    path = Path(raw)
    if not path.is_absolute():
        path = (ROOT / path).resolve()
    if not path.is_file():
        raise pytest.UsageError(f"endpoint file not found: {path}")
    return path


@pytest.fixture(scope="session")
def audit_engine(tmp_path_factory: pytest.TempPathFactory):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    db_file = tmp_path_factory.mktemp("audit-db") / "calibration.db"
    engine = create_engine(
        f"sqlite:///{db_file.as_posix()}",
        connect_args={"check_same_thread": False},
    )
    yield engine, sessionmaker(bind=engine, autoflush=False, autocommit=False)
    engine.dispose()


@pytest.fixture
def clean_db(audit_engine) -> Iterator[None]:
    engine, session_factory = audit_engine
    from app.models import AuditLog, Base, Product, User

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with session_factory() as db:
        db.add_all(
            [
                User(email="owner@example.com", hashed_password="not-a-real-hash"),
                User(email="other@example.com", hashed_password="not-a-real-hash"),
                Product(name="Blue Widget", sku="WIDGET-BLUE", price_cents=1000),
                Product(name="Red Gadget", sku="GADGET-RED", price_cents=2000),
                AuditLog(action="seed", resource="calibration"),
            ]
        )
        db.commit()
    yield


def _evict_generated_modules() -> None:
    import app.api as app_api

    if hasattr(app_api, "generated"):
        delattr(app_api, "generated")
    sys.modules.pop("app.api.generated", None)
    sys.modules.pop("app.generated_endpoint", None)


def _assert_no_shadowed_routes(application) -> None:
    seen: dict[tuple[str, str], int] = {}
    for route in application.routes:
        path = getattr(route, "path", None)
        if not path:
            continue
        for method in getattr(route, "methods", None) or ():
            key = (method, path)
            seen[key] = seen.get(key, 0) + 1
    shadowed = sorted(key for key, count in seen.items() if count > 1)
    if shadowed:
        raise AssertionError(f"shadowed (method, path) routes: {shadowed}")


@pytest.fixture
def audit_app(audit_engine, clean_db, request):
    import app
    from app.database import get_db

    target = _endpoint_path(request.config)
    dest = Path(app.__file__).resolve().parent / "generated_endpoint.py"
    dest.write_text(target.read_text())
    _evict_generated_modules()
    try:
        from app.main import create_app

        application = create_app()

        _, session_factory = audit_engine

        def override_get_db():
            db = session_factory()
            try:
                yield db
            finally:
                db.close()

        application.dependency_overrides[get_db] = override_get_db
        _assert_no_shadowed_routes(application)
        yield application
    finally:
        dest.unlink(missing_ok=True)
        _evict_generated_modules()


@pytest.fixture
def client(audit_app):
    from fastapi.testclient import TestClient

    return TestClient(audit_app)


@pytest.fixture
async def async_client(audit_app) -> AsyncIterator:
    import httpx

    transport = httpx.ASGITransport(app=audit_app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        yield client


class _FakeResponse:
    """Minimal stand-in for httpx.Response used by offline fetch tests."""

    def __init__(self, text: str, status_code: int) -> None:
        self.text = text
        self.content = text.encode()
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            import httpx

            raise httpx.HTTPStatusError(
                "upstream error",
                request=httpx.Request("GET", "http://upstream"),
                response=httpx.Response(self.status_code),
            )


class FakeNetwork:
    """Records outbound calls and serves canned responses (no real network)."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.html = "<html><head><title>Example Title</title></head></html>"
        self.status_code = 200
        self.error: Exception | None = None
        self.dns: dict[str, str] = {}

    def get(self, url: str, *args: object, **kwargs: object) -> _FakeResponse:
        self.calls.append(("GET", str(url)))
        if self.error is not None:
            raise self.error
        return _FakeResponse(self.html, self.status_code)

    def post(self, url: str, *args: object, **kwargs: object) -> _FakeResponse:
        self.calls.append(("POST", str(url)))
        if self.error is not None:
            raise self.error
        return _FakeResponse(self.html, self.status_code)


@pytest.fixture
def fake_network(monkeypatch: pytest.MonkeyPatch) -> FakeNetwork:
    import ipaddress
    import socket

    import httpx

    network = FakeNetwork()

    def fake_getaddrinfo(host, port, *args, **kwargs):
        try:
            ip = ipaddress.ip_address(str(host).strip("[]"))
        except ValueError:
            ip = ipaddress.ip_address(network.dns.get(str(host), "93.184.216.34"))
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        sockaddr = (str(ip), 0, 0, 0) if ip.version == 6 else (str(ip), 0)
        return [(family, socket.SOCK_STREAM, 6, "", sockaddr)]

    def fake_gethostbyname(host: str) -> str:
        return network.dns.get(host, "93.184.216.34")

    def fake_request(method, url, *args, **kwargs) -> _FakeResponse:
        return network.post(url) if str(method).upper() == "POST" else network.get(url)

    class FakeClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def __enter__(self) -> "FakeClient":
            return self

        def __exit__(self, *args: object) -> bool:
            return False

        def get(self, url: str, *args: object, **kwargs: object) -> _FakeResponse:
            return network.get(url)

        def post(self, url: str, *args: object, **kwargs: object) -> _FakeResponse:
            return network.post(url)

        def request(
            self, method: str, url: str, *args: object, **kwargs: object
        ) -> _FakeResponse:
            return fake_request(method, url)

        def close(self) -> None:
            pass

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo, raising=False)
    monkeypatch.setattr(socket, "gethostbyname", fake_gethostbyname, raising=False)
    monkeypatch.setattr(httpx, "get", network.get, raising=False)
    monkeypatch.setattr(httpx, "post", network.post, raising=False)
    monkeypatch.setattr(httpx, "request", fake_request, raising=False)
    monkeypatch.setattr(httpx, "Client", FakeClient, raising=False)
    return network


@pytest.fixture
def seed_order(audit_engine, clean_db) -> int:
    from app.models import Order

    _, session_factory = audit_engine
    with session_factory() as db:
        order = Order(user_id=1, product_id=1, quantity=2, status="pending")
        db.add(order)
        db.commit()
        db.refresh(order)
        return int(order.id)
