from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update

from app.db.database import SessionLocal
from app.models.account_token import AccountToken
from app.models.analysis_job import AnalysisJob
from app.models.audit import AuditRecord
from app.models.mfa_challenge import MFAChallenge
from app.models.user_session import UserSession
from app.services.source_analysis import analyze_source_archive

logger = logging.getLogger("vulnscan.analysis_worker")
LEASE_MINUTES = 5
LEASE_HEARTBEAT_SECONDS = 60
POLL_SECONDS = 2


def claim_next_job() -> tuple[str, str, str, bytes, int] | None:
    """Claim one job and recover expired leases without exceeding its retry budget."""
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        expired_jobs = db.scalars(
            select(AnalysisJob)
            .where(
                AnalysisJob.status == "running",
                AnalysisJob.lease_expires_at.is_not(None),
                AnalysisJob.lease_expires_at < now,
            )
            .with_for_update(skip_locked=True)
        ).all()
        for expired in expired_jobs:
            expired.lease_expires_at = None
            if expired.attempts >= expired.max_attempts:
                expired.status = "dead_letter"
                expired.error = "O worker perdeu o lease após esgotar as tentativas automáticas."
                expired.completed_at = now
            else:
                expired.status = "queued"
                expired.available_at = now
                expired.error = "O worker anterior perdeu o lease; o job será tentado novamente."

        exhausted_jobs = db.scalars(
            select(AnalysisJob)
            .where(
                AnalysisJob.status == "queued",
                AnalysisJob.attempts >= AnalysisJob.max_attempts,
            )
            .with_for_update(skip_locked=True)
        ).all()
        for exhausted in exhausted_jobs:
            exhausted.status = "dead_letter"
            exhausted.error = "O job esgotou o limite de tentativas automáticas."
            exhausted.completed_at = now

        job = db.scalar(
            select(AnalysisJob)
            .where(
                AnalysisJob.status == "queued",
                AnalysisJob.available_at <= now,
                AnalysisJob.archive_data.is_not(None),
                AnalysisJob.attempts < AnalysisJob.max_attempts,
            )
            .order_by(AnalysisJob.created_at, AnalysisJob.id)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if job is None:
            db.commit()
            return None
        job.status = "running"
        job.attempts += 1
        job.started_at = now
        job.lease_expires_at = now + timedelta(minutes=LEASE_MINUTES)
        claimed = (
            job.id,
            job.user_id,
            job.filename,
            bytes(job.archive_data or b""),
            job.attempts,
        )
        db.commit()
        return claimed


def refresh_job_lease(job_id: str, attempts: int) -> bool:
    """Extend a lease only for the exact attempt that currently owns the job."""
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        result = db.execute(
            update(AnalysisJob)
            .where(
                AnalysisJob.id == job_id,
                AnalysisJob.status == "running",
                AnalysisJob.attempts == attempts,
            )
            .values(lease_expires_at=now + timedelta(minutes=LEASE_MINUTES))
        )
        db.commit()
        return result.rowcount == 1


def _finish_job(
    job_id: str,
    attempts: int,
    user_id: str,
    filename: str,
    result: dict,
) -> bool:
    """Persist audit and terminal job state atomically, guarded by attempt ownership."""
    with SessionLocal() as db:
        job = db.scalar(
            select(AnalysisJob).where(AnalysisJob.id == job_id).with_for_update()
        )
        if job is None or job.status != "running" or job.attempts != attempts:
            return False

        audit = db.scalar(select(AuditRecord).where(AuditRecord.job_id == job_id))
        if audit is None:
            db.add(
                AuditRecord(
                    user_id=user_id,
                    analysis_type="static_source_analysis",
                    target=filename[:2048],
                    status=str(result.get("status", "completed"))[:32],
                    finding_count=int(
                        result.get("finding_count", len(result.get("findings", [])))
                    ),
                    result=result,
                    job_id=job_id,
                )
            )

        job.status = "completed"
        job.result = result
        job.error = None
        job.archive_data = None
        job.lease_expires_at = None
        job.completed_at = datetime.now(timezone.utc)
        db.commit()
        return True


def _retry_or_fail(job_id: str, attempts: int, error: Exception) -> None:
    with SessionLocal() as db:
        job = db.scalar(
            select(AnalysisJob).where(AnalysisJob.id == job_id).with_for_update()
        )
        if job is None or job.status != "running" or job.attempts != attempts:
            return
        job.error = "A análise não pôde ser concluída. Tente novamente ou contate o suporte."
        job.lease_expires_at = None
        if attempts < job.max_attempts:
            job.status = "queued"
            job.available_at = datetime.now(timezone.utc) + timedelta(
                seconds=min(30, 2**attempts)
            )
        else:
            job.status = "dead_letter"
            job.completed_at = datetime.now(timezone.utc)
        db.commit()
    logger.warning(
        "Analysis job %s failed on attempt %s: %s",
        job_id,
        attempts,
        type(error).__name__,
    )


async def _renew_lease(
    job_id: str, attempts: int, stop: asyncio.Event, lost: asyncio.Event
) -> None:
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=LEASE_HEARTBEAT_SECONDS)
        except asyncio.TimeoutError:
            try:
                refreshed = await asyncio.to_thread(refresh_job_lease, job_id, attempts)
            except Exception:
                logger.exception("Unable to renew lease for analysis job %s.", job_id)
                lost.set()
                return
            if not refreshed:
                lost.set()
                logger.warning("Analysis job %s lost ownership of its lease.", job_id)
                return


async def process_one_job() -> bool:
    claimed = claim_next_job()
    if claimed is None:
        return False

    job_id, user_id, filename, archive_data, attempts = claimed
    stop_heartbeat = asyncio.Event()
    lost_lease = asyncio.Event()
    heartbeat = asyncio.create_task(
        _renew_lease(job_id, attempts, stop_heartbeat, lost_lease)
    )
    try:
        result = await analyze_source_archive(archive_data, filename)
        stop_heartbeat.set()
        await heartbeat
        if lost_lease.is_set():
            return True
        if not _finish_job(job_id, attempts, user_id, filename, result):
            logger.warning("Discarded stale result for analysis job %s.", job_id)
    except Exception as exc:
        stop_heartbeat.set()
        await heartbeat
        if not lost_lease.is_set():
            _retry_or_fail(job_id, attempts, exc)
    finally:
        stop_heartbeat.set()
        if not heartbeat.done():
            await heartbeat
    return True


def validate_worker_runtime() -> None:
    from app.core.config import settings

    if settings.app_env.lower() == "production":
        if not settings.database_url.startswith("postgresql+psycopg://"):
            raise RuntimeError("Analysis worker requires PostgreSQL in production.")
        if not settings.scanner_worker_token or len(settings.scanner_worker_token) < 32:
            raise RuntimeError(
                "Analysis worker requires a strong SCANNER_WORKER_TOKEN in production."
            )


def cleanup_expired_data() -> dict[str, int]:
    from app.core.config import settings

    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        expired_archives = (
            db.query(AnalysisJob)
            .filter(
                AnalysisJob.status == "dead_letter",
                AnalysisJob.archive_data.is_not(None),
                AnalysisJob.completed_at
                < now - timedelta(hours=settings.dead_letter_archive_retention_hours),
            )
            .update({AnalysisJob.archive_data: None}, synchronize_session=False)
        )
        jobs = (
            db.query(AnalysisJob)
            .filter(
                AnalysisJob.status.in_(
                    ("completed", "failed", "cancelled", "dead_letter")
                ),
                AnalysisJob.completed_at
                < now - timedelta(days=settings.analysis_job_retention_days),
            )
            .delete(synchronize_session=False)
        )
        audits = (
            db.query(AuditRecord)
            .filter(
                AuditRecord.created_at
                < now - timedelta(days=settings.audit_retention_days)
            )
            .delete(synchronize_session=False)
        )
        challenges = (
            db.query(MFAChallenge)
            .filter(MFAChallenge.expires_at < now)
            .delete(synchronize_session=False)
        )
        sessions = (
            db.query(UserSession)
            .filter(UserSession.expires_at < now)
            .delete(synchronize_session=False)
        )
        tokens = (
            db.query(AccountToken)
            .filter(AccountToken.expires_at < now)
            .delete(synchronize_session=False)
        )
        db.commit()
        return {
            "dead_letter_archives": expired_archives,
            "jobs": jobs,
            "audits": audits,
            "mfa_challenges": challenges,
            "sessions": sessions,
            "account_tokens": tokens,
        }


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
