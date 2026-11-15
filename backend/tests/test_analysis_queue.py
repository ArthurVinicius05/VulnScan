from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.database import Base
from app.models.analysis_job import AnalysisJob
from app.models.user import User
from app.services.analysis_queue import AnalysisQuotaExceeded, enqueue_analysis
from app.jobs.runner import claim_next_job, _retry_or_fail

@pytest.fixture
def queue_db(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'queue.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    with sessions() as db:
        user = User(email="queue@example.test", password_hash="hash")
        db.add(user); db.commit(); user_id = user.id
    monkeypatch.setattr("app.services.analysis_queue.settings.max_concurrent_analyses", 2)
    monkeypatch.setattr("app.services.analysis_queue.settings.monthly_analysis_limit", 3)
    monkeypatch.setattr("app.jobs.runner.SessionLocal", sessions)
    yield sessions, user_id
    engine.dispose()

def test_enqueue_persists_archive_and_enforces_concurrency_quota(queue_db):
    sessions, user_id = queue_db
    with sessions() as db:
        first = enqueue_analysis(db, user_id=user_id, filename="first.zip", archive_data=b"zip-one")
        second = enqueue_analysis(db, user_id=user_id, filename="second.zip", archive_data=b"zip-two")
        assert first.status == second.status == "queued"
        assert first.archive_data == b"zip-one"
        with pytest.raises(AnalysisQuotaExceeded, match="simultâneas"):
            enqueue_analysis(db, user_id=user_id, filename="third.zip", archive_data=b"zip-three")

def test_monthly_quota_counts_completed_and_queued_jobs(queue_db, monkeypatch):
    sessions, user_id = queue_db
    monkeypatch.setattr("app.services.analysis_queue.settings.max_concurrent_analyses", 10)
    with sessions() as db:
        for index in range(3):
            db.add(AnalysisJob(user_id=user_id, filename=f"{index}.zip", status="completed",
                archive_data=None, result={}, attempts=1, max_attempts=3,
                created_at=datetime.now(timezone.utc), available_at=datetime.now(timezone.utc)))
        db.commit()
        with pytest.raises(AnalysisQuotaExceeded, match="mensal"):
            enqueue_analysis(db, user_id=user_id, filename="over-quota.zip", archive_data=b"data")

def test_claim_marks_job_running_and_retry_requeues(queue_db):
    sessions, user_id = queue_db
    with sessions() as db:
        job = enqueue_analysis(db, user_id=user_id, filename="retry.zip", archive_data=b"zip")
        job_id = job.id
    claimed = claim_next_job()
    assert claimed is not None and claimed[0] == job_id
    with sessions() as db:
        current = db.get(AnalysisJob, job_id)
        assert current.status == "running"
    _retry_or_fail(job_id, 1, RuntimeError("scanner failure"))
    with sessions() as db:
        current = db.get(AnalysisJob, job_id)
        assert current.status == "queued"
        assert current.archive_data == b"zip"
        assert current.lease_expires_at is None
