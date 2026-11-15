from fastapi import APIRouter, Depends, File, Header, HTTPException, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.api.routes.auth import get_current_user
from app.core.config import settings
from app.models.analysis_job import AnalysisJob
from app.models.user import User
from app.services.analysis_queue import AnalysisQuotaExceeded, enqueue_analysis
from app.services.audit_history import save_audit
from app.services.website_client import scan_website_target
from app.services.zip_inspector import inspect_zip

router = APIRouter(prefix="/analysis", tags=["analysis"])


@router.post("/source-zip", status_code=status.HTTP_202_ACCEPTED)
async def enqueue_source_zip_endpoint(
    file: UploadFile = File(...),
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Envie um arquivo .zip.")
    max_bytes = settings.max_upload_mb * 1024 * 1024
    content = await file.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise HTTPException(status_code=413, detail=f"Arquivo excede o limite de {settings.max_upload_mb} MB.")
    try:
        inspect_zip(content, max_files=settings.max_archive_files,
            max_uncompressed_bytes=settings.max_extracted_mb * 1024 * 1024)
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        job = enqueue_analysis(db, user_id=user.id, filename=file.filename, archive_data=content)
    except AnalysisQuotaExceeded as exc:
        raise HTTPException(status_code=429, detail=exc.message) from exc
    return {"job_id": job.id, "status": job.status,
        "message": "Análise adicionada à fila. Consulte o status para acompanhar o processamento."}


@router.get("/jobs/{job_id}")
def get_analysis_job(job_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    job = db.scalar(select(AnalysisJob).where(AnalysisJob.id == job_id, AnalysisJob.user_id == user.id))
    if job is None:
        raise HTTPException(status_code=404, detail="Análise não encontrada.")
    return {"job_id": job.id, "status": job.status, "error": job.error, "attempts": job.attempts,
        "created_at": job.created_at.isoformat(),
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        "result": job.result if job.status == "completed" else None}


class WebsiteScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    authorized: bool


@router.post("/website")
async def analyze_website_endpoint(
    request: WebsiteScanRequest,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
    user: User = Depends(get_current_user),
):
    if request.authorized is not True:
        raise HTTPException(status_code=403, detail="Confirme que possui autorização para avaliar este alvo.")
    if not settings.enable_website_scan:
        raise HTTPException(status_code=503, detail="A verificação de sites está desativada. Habilite o worker isolado explicitamente.")
    try:
        result = await scan_website_target(request.url, authorized=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if result.get("status") == "unavailable":
        raise HTTPException(status_code=503, detail=result.get("reason"))
    response = {**result, "analysis_type": "website_security_audit",
        "notice": "Verificação passiva limitada à página inicial e aos redirecionamentos validados. Não executa payloads, fuzzing ou exploração. Use somente alvos sob sua autorização."}
    try:
        save_audit(user_id=user.id, analysis_type="website_security_audit", target=request.url, result=response)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="A análise foi concluída, mas não foi possível salvar o histórico.") from exc
    return response
