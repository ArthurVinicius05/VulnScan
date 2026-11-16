from __future__ import annotations

import logging
from hmac import compare_digest

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.core.config import settings
from app.models.analysis_job import AnalysisJob
from app.services.analysis_queue import (
    AnalysisJobArchiveExpired,
    AnalysisJobNotRecoverable,
    requeue_dead_letter_analysis,
)

logger = logging.getLogger("vulnscan.ops")
router = APIRouter(prefix="/ops", tags=["operations"])


def require_operations_token(
    token: str | None = Header(default=None, alias="X-Operations-Token"),
) -> None:
    expected = settings.ops_admin_token
    if not expected:
        raise HTTPException(status_code=503, detail="Operations access is not configured.")
    if not token or not compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="Operations authentication required.")


@router.get("/dead-letter", dependencies=[Depends(require_operations_token)])
def list_dead_letter_jobs(
    db: Session = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=100),
):
    jobs = db.scalars(
        select(AnalysisJob)
        .where(AnalysisJob.status == "dead_letter")
        .order_by(AnalysisJob.completed_at.desc(), AnalysisJob.created_at.desc())
        .limit(limit)
    ).all()
    return {
        "count": len(jobs),
        "jobs": [
            {
                "job_id": job.id,
                "filename": job.filename,
                "status": job.status,
                "attempts": job.attempts,
                "max_attempts": job.max_attempts,
                "archive_available": job.archive_data is not None,
                "error": job.error,
                "created_at": job.created_at.isoformat(),
                "completed_at": job.completed_at.isoformat() if job.completed_at else None,
            }
            for job in jobs
        ],
    }


@router.post(
    "/jobs/{job_id}/retry",
    dependencies=[Depends(require_operations_token)],
)
def recover_dead_letter_job(job_id: str, db: Session = Depends(get_db)):
    try:
        job = requeue_dead_letter_analysis(db, job_id=job_id)
    except AnalysisJobArchiveExpired as exc:
        raise HTTPException(status_code=410, detail=str(exc)) from exc
    except AnalysisJobNotRecoverable as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if job is None:
        raise HTTPException(status_code=404, detail="Analysis job not found.")
    logger.warning("Operations token manually requeued dead-letter job %s.", job.id)
    return {"job_id": job.id, "status": job.status, "message": "Job returned to the analysis queue."}
