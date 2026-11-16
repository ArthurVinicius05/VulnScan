from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.dependencies import get_db
from app.core.config import settings
from app.db.database import Base
from app.main import app
from app.models.analysis_job import AnalysisJob
from app.models.user import User


@pytest.fixture
def ops_client(tmp_path, monkeypatch):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'ops.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(settings, "app_env", "test")
    monkeypatch.setattr(settings, "ops_admin_token", "ops-test-token-" + "x" * 40)

    def override_get_db():
        with sessions() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app) as client:
            yield client, sessions
    finally:
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()


def test_dead_letter_endpoints_require_operations_token(ops_client):
    client, _ = ops_client
    response = client.get("/api/ops/dead-letter")
    assert response.status_code == 401

    response = client.get(
        "/api/ops/dead-letter",
        headers={"X-Operations-Token": "incorrect"},
    )
    assert response.status_code == 401

    response = client.get(
        "/api/ops/dead-letter",
        headers={"X-Operations-Token": settings.ops_admin_token},
    )
    assert response.status_code == 200
    assert response.json() == {"count": 0, "jobs": []}


def test_operations_can_inspect_and_recover_dead_letter_job(ops_client):
    client, sessions = ops_client
    now = datetime.now(timezone.utc)
    with sessions() as db:
        user = User(email="deadletter@example.test", password_hash="hash")
        db.add(user)
        db.flush()
        job = AnalysisJob(
            user_id=user.id,
            filename="recovery.zip",
            status="dead_letter",
            archive_data=b"retained-archive",
            attempts=3,
            max_attempts=3,
            created_at=now,
            available_at=now,
            completed_at=now,
        )
        db.add(job)
        db.commit()
        job_id = job.id

    headers = {"X-Operations-Token": settings.ops_admin_token}
    listed = client.get("/api/ops/dead-letter", headers=headers)
    assert listed.status_code == 200
    assert listed.json()["count"] == 1
    assert listed.json()["jobs"][0]["job_id"] == job_id
    assert listed.json()["jobs"][0]["archive_available"] is True

    recovered = client.post(f"/api/ops/jobs/{job_id}/retry", headers=headers)
    assert recovered.status_code == 200
    assert recovered.json()["status"] == "queued"

    with sessions() as db:
        job = db.get(AnalysisJob, job_id)
        assert job.status == "queued"
        assert job.attempts == 0
        assert job.archive_data == b"retained-archive"


def test_operations_cannot_recover_dead_letter_after_archive_expiry(ops_client):
    client, sessions = ops_client
    now = datetime.now(timezone.utc)
    with sessions() as db:
        user = User(email="expired@example.test", password_hash="hash")
        db.add(user)
        db.flush()
        job = AnalysisJob(
            user_id=user.id,
            filename="expired.zip",
            status="dead_letter",
            archive_data=None,
            attempts=3,
            max_attempts=3,
            created_at=now,
            available_at=now,
            completed_at=now,
        )
        db.add(job)
        db.commit()
        job_id = job.id

    response = client.post(
        f"/api/ops/jobs/{job_id}/retry",
        headers={"X-Operations-Token": settings.ops_admin_token},
    )
    assert response.status_code == 410
