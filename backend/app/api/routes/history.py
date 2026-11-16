from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.api.routes.auth import get_current_user
from app.models.audit import AuditRecord
from app.models.user import User

router = APIRouter(prefix="/history", tags=["history"])


def _set_private_no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "private, no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"


@router.get("")
def list_audits(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    response: Response = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if response is not None:
        _set_private_no_store(response)
    records = db.scalars(
        select(AuditRecord)
        .where(AuditRecord.user_id == user.id)
        .order_by(desc(AuditRecord.created_at), desc(AuditRecord.id))
        .offset(offset).limit(limit)
    ).all()
    return {"items": [{"id": item.id, "analysis_type": item.analysis_type, "target": item.target,
        "status": item.status, "finding_count": item.finding_count, "created_at": item.created_at.isoformat()}
        for item in records], "limit": limit, "offset": offset}


@router.get("/{audit_id}")
def get_audit(audit_id: str, response: Response, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    _set_private_no_store(response)
    record = db.scalar(select(AuditRecord).where(AuditRecord.id == audit_id, AuditRecord.user_id == user.id))
    if record is None:
        raise HTTPException(status_code=404, detail="Análise não encontrada.")
    return {"id": record.id, "analysis_type": record.analysis_type, "target": record.target,
        "status": record.status, "finding_count": record.finding_count,
        "created_at": record.created_at.isoformat(), "result": record.result}
