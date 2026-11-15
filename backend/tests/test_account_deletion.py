from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.dependencies import get_db
from app.core.passwords import hash_password
from app.db.database import Base
from app.main import app
from app.models.analysis_job import AnalysisJob
from app.models.audit import AuditRecord
from app.models.user import User


def test_account_deletion_requires_running_jobs_to_finish_and_removes_live_data(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'delete-account.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    with sessions() as db:
        user = User(email="delete-me@example.com", password_hash=hash_password("correct-horse-battery"),
            email_verified_at=datetime.now(timezone.utc))
        db.add(user)
        db.flush()
        user_id = user.id
        db.add(AnalysisJob(user_id=user_id, filename="queued.zip", status="queued",
            archive_data=b"zip", attempts=0, max_attempts=3))
        db.add(AnalysisJob(user_id=user_id, filename="running.zip", status="running",
            archive_data=b"zip", attempts=1, max_attempts=3))
        db.add(AuditRecord(user_id=user_id, analysis_type="static_source_analysis", target="old.zip",
            status="completed", finding_count=0, result={}))
        db.commit()

    def override_db():
        db = sessions()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    try:
        with TestClient(app) as client:
            login = client.post("/api/auth/login", json={
                "email": "delete-me@example.com", "password": "correct-horse-battery"
            })
            assert login.status_code == 200
            csrf = client.cookies.get("vulnscan_csrf")
            blocked = client.request("DELETE", "/api/auth/me", json={"password": "correct-horse-battery"},
                headers={"X-CSRF-Token": csrf})
            assert blocked.status_code == 409

            with sessions() as db:
                running = db.query(AnalysisJob).filter_by(user_id=user_id, status="running").one()
                running.status = "completed"
                running.completed_at = datetime.now(timezone.utc)
                db.commit()

            deleted = client.request("DELETE", "/api/auth/me", json={"password": "correct-horse-battery"},
                headers={"X-CSRF-Token": csrf})
            assert deleted.status_code == 200
            with sessions() as db:
                assert db.get(User, user_id) is None
                assert db.query(AnalysisJob).filter_by(user_id=user_id).count() == 0
                assert db.query(AuditRecord).filter_by(user_id=user_id).count() == 0
    finally:
        app.dependency_overrides.clear()
        engine.dispose()
