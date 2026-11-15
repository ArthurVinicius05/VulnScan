from sqlalchemy.orm import Session

from app.db.database import SessionLocal
from app.models.audit import AuditRecord


def save_audit(*, user_id: str, analysis_type: str, target: str, result: dict) -> None:
    """Persist a completed audit without retaining uploaded source contents."""
    db: Session = SessionLocal()
    try:
        db.add(
            AuditRecord(
                user_id=user_id,
                analysis_type=analysis_type,
                target=target[:2048],
                status=str(result.get("status", "completed"))[:32],
                finding_count=int(result.get("finding_count", len(result.get("findings", [])))),
                result=result,
            )
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
