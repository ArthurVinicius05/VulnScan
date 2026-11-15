from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.database import Base
from app.models.analysis_job import AnalysisJob
from app.models.user import User
from app.services.analysis_queue import AnalysisQuotaExceeded, AnalysisJobNotCancellable, cancel_queued_analysis, enqueue_analysis
from app.jobs.runner import claim_next_job, _retry_or_fail, cleanup_expired_data
from app.models.audit import AuditRecord
from app.models.account_token import AccountToken
from app.models.mfa_challenge import MFAChallenge
from app.models.user_session import UserSession

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
    monkeypatch.setattr("app.services.analysis_queue.settings.max_queued_storage_mb", 50)
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

def test_queued_archive_storage_is_bounded_per_account(queue_db, monkeypatch):
    sessions, user_id = queue_db
    monkeypatch.setattr("app.services.analysis_queue.settings.max_concurrent_analyses", 10)
    monkeypatch.setattr("app.services.analysis_queue.settings.max_queued_storage_mb", 10)
    with sessions() as db:
        enqueue_analysis(db, user_id=user_id, filename="six.zip", archive_data=b"x" * (6 * 1024 * 1024))
        with pytest.raises(AnalysisQuotaExceeded, match="armazenamento temporário"):
            enqueue_analysis(db, user_id=user_id, filename="five.zip", archive_data=b"x" * (5 * 1024 * 1024))


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


def test_retention_cleanup_removes_expired_records_and_old_jobs(queue_db, monkeypatch):
    sessions, user_id = queue_db
    monkeypatch.setattr("app.core.config.settings.analysis_job_retention_days", 30)
    monkeypatch.setattr("app.core.config.settings.audit_retention_days", 180)
    old = datetime(2020, 1, 1, tzinfo=timezone.utc)
    with sessions() as db:
        db.add(AnalysisJob(user_id=user_id, filename="old.zip", status="completed", archive_data=None,
            result={}, attempts=1, max_attempts=3, created_at=old, available_at=old, completed_at=old))
        db.add(AuditRecord(user_id=user_id, analysis_type="static_source_analysis", target="old.zip",
            status="completed", finding_count=0, result={}, created_at=old))
        db.add(UserSession(user_id=user_id, token_hash="d" * 64, expires_at=old, created_at=old))
        db.add(AccountToken(user_id=user_id, token_hash="e" * 64, purpose="verify_email", expires_at=old, created_at=old))
        db.add(MFAChallenge(user_id=user_id, token_hash="f" * 64, attempts=0, expires_at=old, created_at=old))
        db.commit()
    counts = cleanup_expired_data()
    assert counts == {"jobs": 1, "audits": 1, "mfa_challenges": 1, "sessions": 1, "account_tokens": 1}


def test_cancel_queued_job_releases_active_slot_and_upload_storage(queue_db, monkeypatch):
    sessions, user_id = queue_db
    monkeypatch.setattr("app.services.analysis_queue.settings.max_concurrent_analyses", 1)
    monkeypatch.setattr("app.services.analysis_queue.settings.max_queued_storage_mb", 10)
    with sessions() as db:
        job = enqueue_analysis(db, user_id=user_id, filename="cancel.zip", archive_data=b"x" * 1024)
        cancelled = cancel_queued_analysis(db, user_id=user_id, job_id=job.id)
        assert cancelled.status == "cancelled"
        assert cancelled.archive_data is None
        replacement = enqueue_analysis(db, user_id=user_id, filename="next.zip", archive_data=b"y" * 1024)
        assert replacement.status == "queued"


def test_running_analysis_cannot_be_cancelled(queue_db):
    sessions, user_id = queue_db
    with sessions() as db:
        job = enqueue_analysis(db, user_id=user_id, filename="running.zip", archive_data=b"zip")
        job.status = "running"
        db.commit()
        with pytest.raises(AnalysisJobNotCancellable):
            cancel_queued_analysis(db, user_id=user_id, job_id=job.id)
