from fastapi import APIRouter, File, HTTPException, UploadFile

from app.core.config import settings
from app.services.dependency_inventory import inventory_dependency_manifests
from app.services.source_analyzer import analyze_source_zip
from app.services.worker_client import scan_python_archive
from app.services.zip_inspector import inspect_zip

router = APIRouter(prefix="/analysis", tags=["analysis"])


@router.post("/source-zip")
async def analyze_source_zip_endpoint(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Envie um arquivo .zip.")

    max_bytes = settings.max_upload_mb * 1024 * 1024
    content = await file.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise HTTPException(status_code=413, detail=f"Arquivo excede o limite de {settings.max_upload_mb} MB.")

    try:
        metadata = inspect_zip(
            content,
            max_files=settings.max_archive_files,
            max_uncompressed_bytes=settings.max_extracted_mb * 1024 * 1024,
        )
        heuristic_findings = analyze_source_zip(content)
        tool_result = await scan_python_archive(content)
        dependency_result = inventory_dependency_manifests(content)
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    findings = heuristic_findings + tool_result.get("findings", [])
    return {
        "status": "completed",
        "analysis_type": "static_source_analysis",
        "filename": file.filename,
        "notice": "Achados heurísticos e resultados de ferramentas estáticas. Eles não comprovam explorabilidade e exigem validação manual.",
        "finding_count": len(findings),
        "findings": findings,
        "scanner_tools": tool_result,
        "dependencies": dependency_result,
        **metadata,
    }
