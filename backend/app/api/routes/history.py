from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.core.auth import require_api_key
from app.db.database import SessionLocal
from app.models.audit import AuditRecord

router = APIRouter(
    prefix="/history",
    tags=["history"],
    dependencies=[Depends(require_api_key)],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("")
def list_audits(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    records = db.scalars(
        select(AuditRecord)
        .order_by(desc(AuditRecord.created_at), desc(AuditRecord.id))
        .offset(offset)
        .limit(limit)
    ).all()
    return {
        "items": [
            {
                "id": item.id,
                "analysis_type": item.analysis_type,
                "target": item.target,
                "status": item.status,
                "finding_count": item.finding_count,
                "created_at": item.created_at.isoformat(),
            }
            for item in records
        ],
        "limit": limit,
        "offset": offset,
    }


@router.get("/{audit_id}")
def get_audit(audit_id: str, db: Session = Depends(get_db)):
    record = db.get(AuditRecord, audit_id)
    if record is None:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Análise não encontrada.")
    return {
        "id": record.id,
        "analysis_type": record.analysis_type,
        "target": record.target,
        "status": record.status,
        "finding_count": record.finding_count,
        "created_at": record.created_at.isoformat(),
        "result": record.result,
    }
