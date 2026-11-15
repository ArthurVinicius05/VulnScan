from __future__ import annotations
import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from app.db.database import SessionLocal
from app.models.analysis_job import AnalysisJob
from app.models.audit import AuditRecord
from app.models.account_token import AccountToken
from app.models.mfa_challenge import MFAChallenge
from app.models.user_session import UserSession
from app.services.audit_history import save_audit
from app.services.source_analysis import analyze_source_archive

logger = logging.getLogger("vulnscan.analysis_worker")
LEASE_MINUTES = 5
POLL_SECONDS = 2

def claim_next_job() -> tuple[str, str, str, bytes, int] | None:
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        db.query(AnalysisJob).filter(AnalysisJob.status == "running",
            AnalysisJob.lease_expires_at.is_not(None), AnalysisJob.lease_expires_at < now).update(
            {AnalysisJob.status: "queued", AnalysisJob.lease_expires_at: None}, synchronize_session=False)
        job = db.scalar(select(AnalysisJob).where(AnalysisJob.status == "queued",
            AnalysisJob.available_at <= now, AnalysisJob.archive_data.is_not(None))
            .order_by(AnalysisJob.created_at, AnalysisJob.id).with_for_update(skip_locked=True).limit(1))
        if job is None:
            db.commit()
            return None
        job.status = "running"
        job.attempts += 1
        job.started_at = now
        job.lease_expires_at = now + timedelta(minutes=LEASE_MINUTES)
        claimed = (job.id, job.user_id, job.filename, bytes(job.archive_data or b""), job.attempts)
        db.commit()
        return claimed

def _finish_job(job_id: str, result: dict) -> None:
    with SessionLocal() as db:
        job = db.get(AnalysisJob, job_id)
        if job is None: return
        job.status, job.result, job.error = "completed", result, None
        job.archive_data = None
        job.lease_expires_at = None
        job.completed_at = datetime.now(timezone.utc)
        db.commit()

def _retry_or_fail(job_id: str, attempts: int, error: Exception) -> None:
    with SessionLocal() as db:
        job = db.get(AnalysisJob, job_id)
        if job is None: return
        job.error = "A análise não pôde ser concluída. Tente novamente ou contate o suporte."
        job.lease_expires_at = None
        if attempts < job.max_attempts:
            job.status = "queued"
            job.available_at = datetime.now(timezone.utc) + timedelta(seconds=min(30, 2 ** attempts))
        else:
            job.status = "failed"
            job.archive_data = None
            job.completed_at = datetime.now(timezone.utc)
        db.commit()
    logger.warning("Analysis job %s failed on attempt %s: %s", job_id, attempts, type(error).__name__)

async def process_one_job() -> bool:
    claimed = claim_next_job()
    if claimed is None: return False
    job_id, user_id, filename, archive_data, attempts = claimed
    try:
        result = await analyze_source_archive(archive_data, filename)
        save_audit(user_id=user_id, analysis_type="static_source_analysis",
            target=filename, result=result, job_id=job_id)
        _finish_job(job_id, result)
    except Exception as exc:
        _retry_or_fail(job_id, attempts, exc)
    return True

def validate_worker_runtime() -> None:
    from app.core.config import settings
    if settings.app_env.lower() == "production":
        if not settings.database_url.startswith("postgresql+psycopg://"):
            raise RuntimeError("Analysis worker requires PostgreSQL in production.")
        if not settings.scanner_worker_token or len(settings.scanner_worker_token) < 32:
            raise RuntimeError("Analysis worker requires a strong SCANNER_WORKER_TOKEN in production.")

def cleanup_expired_data() -> dict[str, int]:
    from app.core.config import settings
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        jobs = db.query(AnalysisJob).filter(AnalysisJob.status.in_(("completed", "failed")),
            AnalysisJob.completed_at < now - timedelta(days=settings.analysis_job_retention_days)).delete(synchronize_session=False)
        audits = db.query(AuditRecord).filter(AuditRecord.created_at < now - timedelta(days=settings.audit_retention_days)).delete(synchronize_session=False)
        challenges = db.query(MFAChallenge).filter(MFAChallenge.expires_at < now).delete(synchronize_session=False)
        sessions = db.query(UserSession).filter(UserSession.expires_at < now).delete(synchronize_session=False)
        tokens = db.query(AccountToken).filter(AccountToken.expires_at < now).delete(synchronize_session=False)
        db.commit()
        return {"jobs": jobs, "audits": audits, "mfa_challenges": challenges, "sessions": sessions, "account_tokens": tokens}

async def run_forever() -> None:
    validate_worker_runtime()
    last_cleanup = 0.0
    while True:
        if time.monotonic() - last_cleanup >= 24 * 60 * 60:
            try:
                cleanup_expired_data()
            except Exception:
                logger.exception("Scheduled retention cleanup failed.")
            last_cleanup = time.monotonic()
        if not await process_one_job():
            await asyncio.sleep(POLL_SECONDS)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_forever())
