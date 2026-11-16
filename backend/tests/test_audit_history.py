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



def test_audit_comparison_reports_added_resolved_and_score_delta(audit_client):
    client, _, user_id = audit_client
    baseline_id = audit_history.save_audit(
        user_id=user_id, analysis_type="static_source_analysis", target="project.zip",
        result={"findings": [
            {"rule_id": "A", "file": "app.py", "line": 20, "title": "Issue A", "severity": "high"},
            {"rule_id": "B", "file": "db.py", "title": "Issue B", "severity": "medium"},
        ], "security_score": {"value": 70, "model_version": "1.0"}},
    )
    candidate_id = audit_history.save_audit(
        user_id=user_id, analysis_type="static_source_analysis", target="project.zip",
        result={"findings": [
            {"rule_id": "A", "file": "app.py", "line": 45, "title": "Issue A", "severity": "high"},
            {"rule_id": "C", "file": "web.py", "title": "Issue C", "severity": "low"},
        ], "security_score": {"value": 82, "model_version": "1.0"}},
    )
    response = client.get(f"/api/history/compare/{baseline_id}/{candidate_id}")
    assert response.status_code == 200
    payload = response.json()
    assert payload["findings"] == {
        "details_available": True, "added": 1, "resolved": 1, "unchanged": 1, "baseline_total": 2, "candidate_total": 2
    }
    assert payload["score"] == {
        "comparable": True, "baseline": 70, "candidate": 82, "delta": 12, "model_version": "1.0"
    }
    assert response.headers["cache-control"] == "private, no-store, max-age=0"


def test_audit_comparison_does_not_disclose_other_users_records(audit_client):
    client, test_sessions, user_id = audit_client
    baseline_id = audit_history.save_audit(
        user_id=user_id, analysis_type="static_source_analysis", target="private.zip", result={"findings": []}
    )
    with test_sessions() as db:
        other = User(email="compare-other@example.com", password_hash="not-used")
        db.add(other)
        db.commit()
        other_id = other.id
    candidate_id = audit_history.save_audit(
        user_id=other_id, analysis_type="static_source_analysis", target="secret.zip", result={"findings": []}
    )
    assert client.get(f"/api/history/compare/{baseline_id}/{candidate_id}").status_code == 404


def test_audit_comparison_rejects_different_analysis_types(audit_client):
    client, _, user_id = audit_client
    baseline_id = audit_history.save_audit(
        user_id=user_id, analysis_type="static_source_analysis", target="project.zip", result={"findings": []}
    )
    candidate_id = audit_history.save_audit(
        user_id=user_id, analysis_type="website_security_audit", target="example.test", result={"findings": []}
    )
    assert client.get(f"/api/history/compare/{baseline_id}/{candidate_id}").status_code == 422


def test_audit_comparison_rejects_same_record(audit_client):
    client, _, user_id = audit_client
    audit_id = audit_history.save_audit(
        user_id=user_id, analysis_type="static_source_analysis", target="project.zip", result={"findings": []}
    )
    assert client.get(f"/api/history/compare/{audit_id}/{audit_id}").status_code == 422



def test_audit_comparison_marks_legacy_finding_details_unavailable(audit_client):
    client, _, user_id = audit_client
    baseline_id = audit_history.save_audit(
        user_id=user_id, analysis_type="static_source_analysis", target="project.zip",
        result={"finding_count": 3},
    )
    candidate_id = audit_history.save_audit(
        user_id=user_id, analysis_type="static_source_analysis", target="project.zip",
        result={"findings": [], "finding_count": 0},
    )
    response = client.get(f"/api/history/compare/{baseline_id}/{candidate_id}")
    assert response.status_code == 200
    assert response.json()["findings"]["details_available"] is False


def test_audit_comparison_only_compares_matching_score_model_versions(audit_client):
    client, _, user_id = audit_client
    baseline_id = audit_history.save_audit(
        user_id=user_id, analysis_type="static_source_analysis", target="project.zip",
        result={"findings": [], "security_score": {"value": 70, "model_version": "1.0"}},
    )
    candidate_id = audit_history.save_audit(
        user_id=user_id, analysis_type="static_source_analysis", target="project.zip",
        result={"findings": [], "security_score": {"value": 90, "model_version": "2.0"}},
    )
    response = client.get(f"/api/history/compare/{baseline_id}/{candidate_id}")
    assert response.status_code == 200
    assert response.json()["score"]["comparable"] is False
    assert response.json()["score"]["delta"] is None



def test_audit_comparison_requires_authentication(audit_client):
    client, _, user_id = audit_client
    baseline_id = audit_history.save_audit(
        user_id=user_id, analysis_type="static_source_analysis", target="project.zip", result={"findings": []}
    )
    candidate_id = audit_history.save_audit(
        user_id=user_id, analysis_type="static_source_analysis", target="project.zip", result={"findings": []}
    )
    client.cookies.delete("vulnscan_session")
    assert client.get(f"/api/history/compare/{baseline_id}/{candidate_id}").status_code == 401
