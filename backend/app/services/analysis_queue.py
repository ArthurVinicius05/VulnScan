from datetime import datetime, timezone
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from app.core.config import settings
from app.models.analysis_job import AnalysisJob
from app.models.user import User

class AnalysisQuotaExceeded(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)

def enqueue_analysis(db: Session, *, user_id: str, filename: str, archive_data: bytes) -> AnalysisJob:
    """Persist the upload and queue row atomically; PostgreSQL row locking serializes account quotas."""
    user = db.scalar(select(User).where(User.id == user_id).with_for_update())
    if user is None:
        raise AnalysisQuotaExceeded("Conta não encontrada.")
    now = datetime.now(timezone.utc)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    active_count = db.scalar(select(func.count()).select_from(AnalysisJob).where(
        AnalysisJob.user_id == user_id, AnalysisJob.status.in_(("queued", "running")))) or 0
    if active_count >= settings.max_concurrent_analyses:
        raise AnalysisQuotaExceeded("Limite de análises simultâneas atingido. Aguarde uma análise terminar.")
    monthly_count = db.scalar(select(func.count()).select_from(AnalysisJob).where(
        AnalysisJob.user_id == user_id, AnalysisJob.created_at >= month_start)) or 0
    if monthly_count >= settings.monthly_analysis_limit:
        raise AnalysisQuotaExceeded("Cota mensal de análises atingida.")
    queued_storage = db.scalar(select(func.coalesce(func.sum(func.length(AnalysisJob.archive_data)), 0)).where(
        AnalysisJob.user_id == user_id,
        AnalysisJob.status.in_(("queued", "running")),
        AnalysisJob.archive_data.is_not(None),
    )) or 0
    storage_limit = settings.max_queued_storage_mb * 1024 * 1024
    if queued_storage + len(archive_data) > storage_limit:
        raise AnalysisQuotaExceeded("Limite de armazenamento temporário de análises atingido. Aguarde a fila liberar espaço.")
    job = AnalysisJob(user_id=user_id, filename=filename[:255], status="queued",
        archive_data=archive_data, created_at=now, available_at=now)
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


class AnalysisJobNotCancellable(Exception):
    pass


def cancel_queued_analysis(db: Session, *, user_id: str, job_id: str) -> AnalysisJob | None:
    job = db.scalar(select(AnalysisJob).where(
        AnalysisJob.id == job_id, AnalysisJob.user_id == user_id
    ).with_for_update())
    if job is None:
        return None
    if job.status != "queued":
        raise AnalysisJobNotCancellable("Somente análises ainda na fila podem ser canceladas.")
    job.status = "cancelled"
    job.archive_data = None
    job.error = "Cancelado pelo usuário."
    job.completed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(job)
    return job
