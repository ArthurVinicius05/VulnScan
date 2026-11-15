import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.database import Base
from app.main import app
from app.models.audit import AuditRecord
from app.services import audit_history
from app.api.routes import history


@pytest.fixture
def audit_client(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'history.db'}")
    Base.metadata.create_all(engine)
    test_sessions = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(audit_history, "SessionLocal", test_sessions)
    monkeypatch.setattr(history, "SessionLocal", test_sessions)
    with TestClient(app) as client:
        yield client, test_sessions
    engine.dispose()


def test_audit_is_persisted_and_returned_without_raw_upload(audit_client):
    client, test_sessions = audit_client
    audit_history.save_audit(
        analysis_type="static_source_analysis",
        target="project.zip",
        result={
            "status": "completed",
            "analysis_type": "static_source_analysis",
            "finding_count": 1,
            "findings": [{"rule_id": "TEST001", "evidence": "secret value redacted"}],
        },
    )

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
        assert record is not None
        assert "raw_archive" not in record.result


def test_history_pagination_validation(audit_client):
    client, _ = audit_client
    response = client.get("/api/history?limit=1000")
    assert response.status_code == 422


def test_history_missing_record_returns_404(audit_client):
    client, _ = audit_client
    response = client.get("/api/history/not-a-real-id")
    assert response.status_code == 404
