from fastapi import APIRouter, Depends, File, Header, HTTPException, UploadFile
from pydantic import BaseModel, Field

from app.api.routes.auth import get_current_user
from app.models.user import User
from app.core.config import settings
from app.services.audit_history import save_audit
from app.services.dependency_inventory import inventory_dependency_manifests
from app.services.osv_client import scan_dependencies
from app.services.source_analyzer import analyze_source_zip, source_analysis_coverage
from app.services.worker_client import scan_python_archive
from app.services.website_client import scan_website_target
from app.services.zip_inspector import inspect_zip

router = APIRouter(
    prefix="/analysis",
    tags=["analysis"],
)


@router.post("/source-zip")
async def analyze_source_zip_endpoint(file: UploadFile = File(...), csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"), user: User = Depends(get_current_user)):
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
        heuristic_coverage = source_analysis_coverage(content)
        heuristic_findings = analyze_source_zip(content)
        tool_result = await scan_python_archive(content)
        dependency_result = inventory_dependency_manifests(content)
        osv_result = await scan_dependencies(content)
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    findings = heuristic_findings + tool_result.get("findings", []) + osv_result.get("findings", [])
    tool_statuses = [
        item.get("status", "unknown")
        for item in tool_result.get("tools", [])
    ]
    security_statuses = [
        item.get("status", "unknown")
        for item in tool_result.get("security_tools", [])
    ] + [osv_result.get("status", "unknown")]
    heuristic_partial = (
        heuristic_coverage["files_over_file_limit"] > 0
        or heuristic_coverage["files_over_total_limit"] > 0
        or len(heuristic_findings) >= heuristic_coverage["max_findings"]
    )
    scanner_partial = (
        any(value not in {"completed", "skipped"} for value in tool_statuses + security_statuses)
        or dependency_result.get("status") != "completed"
    )
    analysis_status = "partial" if heuristic_partial or scanner_partial or tool_result.get("status") in {"partial", "unavailable"} else "completed"
    response = {
        "status": analysis_status,
        "coverage": {
            "heuristics": {
                **heuristic_coverage,
                "findings_returned": len(heuristic_findings),
                "possibly_truncated_by_finding_limit": len(heuristic_findings) >= heuristic_coverage["max_findings"],
            },
            "python_tools": tool_result.get("coverage", {}),
            "overall": analysis_status,
        },
        "analysis_type": "static_source_analysis",
        "filename": file.filename,
        "notice": (
            "Análise parcial: alguns scanners, arquivos ou achados foram limitados ou ficaram indisponíveis. "
            "Consulte coverage e scanner_tools antes de interpretar a ausência de achados. "
            "Os resultados não comprovam explorabilidade e exigem validação manual."
            if analysis_status == "partial"
            else "Achados heurísticos e resultados de ferramentas estáticas. Eles não comprovam explorabilidade e exigem validação manual."
        ),
        "finding_count": len(findings),
        "findings": findings,
        "scanner_tools": {
            **tool_result,
            "security_tools": [
                item for item in tool_result.get("security_tools", [])
                if item.get("name") != "OSV-Scanner"
            ] + [osv_result],
        },
        "dependencies": dependency_result,
        **metadata,
    }
    try:
        save_audit(user_id=user.id, analysis_type="static_source_analysis", target=file.filename, result=response)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="A análise foi concluída, mas não foi possível salvar o histórico.") from exc
    return response


class WebsiteScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    authorized: bool


@router.post("/website")
async def analyze_website_endpoint(request: WebsiteScanRequest, csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"), user: User = Depends(get_current_user)):
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
    response = {
        **result,
        "analysis_type": "website_security_audit",
        "notice": "Verificação passiva limitada à página inicial e aos redirecionamentos validados. Não executa payloads, fuzzing ou exploração. Use somente alvos sob sua autorização.",
    }
    try:
        save_audit(user_id=user.id, analysis_type="website_security_audit", target=request.url, result=response)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="A análise foi concluída, mas não foi possível salvar o histórico.") from exc
    return response
