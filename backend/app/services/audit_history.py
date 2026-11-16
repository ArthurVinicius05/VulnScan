from sqlalchemy import select
from sqlalchemy.orm import Session
from app.db.database import SessionLocal
from app.models.audit import AuditRecord

def save_audit(*, user_id: str, analysis_type: str, target: str, result: dict, job_id: str | None = None) -> str:
    """Persist a completed audit without retaining uploaded source contents."""
    db: Session = SessionLocal()
    try:
        if job_id:
            existing = db.scalar(select(AuditRecord).where(AuditRecord.job_id == job_id))
            if existing is not None:
                return existing.id
        record = AuditRecord(
            user_id=user_id,
            analysis_type=analysis_type,
            target=target[:2048],
            status=str(result.get("status", "completed"))[:32],
            finding_count=int(result.get("finding_count", len(result.get("findings", [])))),
            result=result,
            job_id=job_id,
        )
        db.add(record)
        db.commit()
        return record.id
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
