from fastapi import APIRouter, File, HTTPException, UploadFile

from app.core.config import settings
from app.services.zip_inspector import inspect_zip

router = APIRouter(prefix="/analysis", tags=["analysis"])


@router.post("/source-zip")
async def analyze_source_zip(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Envie um arquivo .zip.")

    max_bytes = settings.max_upload_mb * 1024 * 1024
    content = await file.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise HTTPException(status_code=413, detail=f"Arquivo excede o limite de {settings.max_upload_mb} MB.")

    try:
        result = inspect_zip(
            content,
            max_files=settings.max_archive_files,
            max_uncompressed_bytes=settings.max_extracted_mb * 1024 * 1024,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "status": "completed",
        "analysis_type": "source_fingerprint",
        "filename": file.filename,
        "notice": "Identificação de estrutura e tecnologias; scanners de vulnerabilidade ainda não integrados.",
        **result,
    }
