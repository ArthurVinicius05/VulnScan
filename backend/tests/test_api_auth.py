import hashlib
from collections.abc import Generator
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.dependencies import get_db
from app.db.database import Base
from app.main import app
from app.models.user import User
from app.models.user_session import UserSession


def test_analysis_routes_require_individual_session():
    client = TestClient(app, client=("127.0.0.13", 12345))
    response = client.post("/api/analysis/website", json={"url": "https://example.org", "authorized": False})
    assert response.status_code == 401


def test_analysis_routes_accept_valid_individual_session(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'auth-route.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    token = "valid-analysis-session"
    with sessions() as db:
        user = User(email="scanner@example.com", password_hash="unused")
        db.add(user)
        db.flush()
        db.add(UserSession(user_id=user.id, token_hash=hashlib.sha256(token.encode()).hexdigest(),
            created_at=datetime.now(timezone.utc), expires_at=datetime.now(timezone.utc) + timedelta(hours=1)))
        db.commit()

    def override_db() -> Generator:
        db = sessions()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    try:
        client = TestClient(app)
        client.cookies.set("vulnscan_session", token)
        client.cookies.set("vulnscan_csrf", "csrf-valid")
        response = client.post("/api/analysis/website", headers={"X-CSRF-Token": "csrf-valid"},
            json={"url": "https://example.org", "authorized": False})
        assert response.status_code == 403
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def test_health_endpoint_remains_public():
    response = TestClient(app, client=("127.0.0.14", 12345)).get("/api/health")
    assert response.status_code == 200


def test_upload_rejects_unauthenticated_request_before_multipart_parsing():
    client = TestClient(app, client=("127.0.0.15", 12345))
    response = client.post(
        "/api/analysis/source-zip",
        content=b"not a valid multipart body",
        headers={"Content-Type": "multipart/form-data; boundary=missing"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Autenticação necessária."


def test_upload_rejects_oversized_content_length_before_multipart_parsing(monkeypatch):
    from app.middleware import upload_auth

    monkeypatch.setattr(upload_auth.settings, "max_upload_mb", 1)
    client = TestClient(app, client=("127.0.0.16", 12345))
    response = client.post(
        "/api/analysis/source-zip",
        content=b"",
        headers={
            "Content-Type": "multipart/form-data; boundary=missing",
            "Content-Length": str(3 * 1024 * 1024),
        },
    )
    assert response.status_code == 413
