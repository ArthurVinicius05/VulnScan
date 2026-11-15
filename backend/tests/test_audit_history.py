import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.dependencies import get_db
from app.db.database import Base
from app.main import app
from app.models.audit import AuditRecord
from app.models.user import User
from app.models.user_session import UserSession
from app.services import audit_history


@pytest.fixture
def audit_client(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'history.db'}")
    Base.metadata.create_all(engine)
    test_sessions = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(audit_history, "SessionLocal", test_sessions)

    def override_db():
        db = test_sessions()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    token = "test-session-token"
    with test_sessions() as db:
        user = User(email="owner@example.com", password_hash="not-used")
        db.add(user)
        db.flush()
        db.add(UserSession(user_id=user.id, token_hash=hashlib.sha256(token.encode()).hexdigest(),
            created_at=datetime.now(timezone.utc), expires_at=datetime.now(timezone.utc) + timedelta(hours=1)))
        db.commit()
        user_id = user.id
    with TestClient(app) as client:
        client.cookies.set("vulnscan_session", token)
        client.cookies.set("vulnscan_csrf", "test-csrf-token")
        yield client, test_sessions, user_id
    app.dependency_overrides.clear()
    engine.dispose()


def test_audit_is_persisted_and_returned_without_raw_upload(audit_client):
    client, test_sessions, user_id = audit_client
    audit_history.save_audit(user_id=user_id, analysis_type="static_source_analysis", target="project.zip",
        result={"status": "completed", "analysis_type": "static_source_analysis", "finding_count": 1,
            "findings": [{"rule_id": "TEST001", "evidence": "secret value redacted"}]})
    response = client.get("/api/history")
    assert response.status_code == 200
    payload = response.json()
    assert len(payload["items"]) == 1
    audit_id = payload["items"][0]["id"]
    assert payload["items"][0]["target"] == "project.zip"
    detail = client.get(f"/api/history/{audit_id}")
    assert detail.status_code == 200
    assert detail.json()["result"]["findings"][0]["evidence"] == "secret value redacted"
    with test_sessions() as db:
        record = db.get(AuditRecord, audit_id)
        assert record is not None and record.user_id == user_id
        assert "raw_archive" not in record.result


def test_history_is_private_between_users(audit_client):
    client, test_sessions, user_id = audit_client
    audit_history.save_audit(user_id=user_id, analysis_type="static_source_analysis", target="private.zip", result={"findings": []})
    with test_sessions() as db:
        other = User(email="other@example.com", password_hash="not-used")
        db.add(other)
        db.commit()
        other_id = other.id
    # A valid session belonging to a different account cannot read the first user's record.
    from app.models.user_session import UserSession
    token = "other-session-token"
    with test_sessions() as db:
        db.add(UserSession(user_id=other_id, token_hash=hashlib.sha256(token.encode()).hexdigest(),
            created_at=datetime.now(timezone.utc), expires_at=datetime.now(timezone.utc) + timedelta(hours=1)))
        db.commit()
    response = client.get("/api/history")
    assert response.status_code == 200 and response.json()["items"][0]["target"] == "private.zip"
    audit_id = response.json()["items"][0]["id"]
    client.cookies.set("vulnscan_session", token)
    assert client.get("/api/history").json()["items"] == []
    assert client.get(f"/api/history/{audit_id}").status_code == 404


def test_history_requires_authentication(audit_client):
    client, _, _ = audit_client
    client.cookies.delete("vulnscan_session")
    assert client.get("/api/history").status_code == 401


def test_history_pagination_validation(audit_client):
    client, _, _ = audit_client
    assert client.get("/api/history?limit=1000").status_code == 422


def test_history_missing_record_returns_404(audit_client):
    client, _, _ = audit_client
    assert client.get("/api/history/not-a-real-id").status_code == 404
