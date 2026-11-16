from app.core.config import settings
from app.services.dependency_inventory import inventory_dependency_manifests
from app.services.osv_client import scan_dependencies
from app.services.source_analyzer import analyze_source_zip, source_analysis_coverage
from app.services.security_score import calculate_security_score
from app.services.worker_client import scan_python_archive
from app.services.zip_inspector import inspect_zip

async def analyze_source_archive(content: bytes, filename: str) -> dict:
    metadata = inspect_zip(content, max_files=settings.max_archive_files,
        max_uncompressed_bytes=settings.max_extracted_mb * 1024 * 1024)
    heuristic_coverage = source_analysis_coverage(content)
    heuristic_findings = analyze_source_zip(content)
    tool_result = await scan_python_archive(content)
    dependency_result = inventory_dependency_manifests(content)
    osv_result = await scan_dependencies(content)
    findings = heuristic_findings + tool_result.get("findings", []) + osv_result.get("findings", [])
    tool_statuses = [item.get("status", "unknown") for item in tool_result.get("tools", [])]
    security_statuses = [item.get("status", "unknown") for item in tool_result.get("security_tools", [])] + [osv_result.get("status", "unknown")]
    heuristic_partial = (heuristic_coverage["files_over_file_limit"] > 0
        or heuristic_coverage["files_over_total_limit"] > 0
        or len(heuristic_findings) >= heuristic_coverage["max_findings"])
    scanner_partial = (any(value not in {"completed", "skipped"} for value in tool_statuses + security_statuses)
        or dependency_result.get("status") != "completed")
    analysis_status = "partial" if heuristic_partial or scanner_partial or tool_result.get("status") in {"partial", "unavailable"} else "completed"
    coverage = {"heuristics": {**heuristic_coverage, "findings_returned": len(heuristic_findings),
        "possibly_truncated_by_finding_limit": len(heuristic_findings) >= heuristic_coverage["max_findings"]},
        "python_tools": tool_result.get("coverage", {}), "overall": analysis_status}
    security_score = calculate_security_score(findings, analysis_status=analysis_status, coverage=coverage)
    return {
        "status": analysis_status,
        "coverage": coverage,
        "security_score": security_score,
        "analysis_type": "static_source_analysis", "filename": filename,
        "notice": ("Análise parcial: alguns scanners, arquivos ou achados foram limitados ou ficaram indisponíveis. Consulte coverage e scanner_tools antes de interpretar a ausência de achados. Os resultados não comprovam explorabilidade e exigem validação manual."
            if analysis_status == "partial" else "Achados heurísticos e resultados de ferramentas estáticas. Eles não comprovam explorabilidade e exigem validação manual."),
        "finding_count": len(findings), "findings": findings,
        "scanner_tools": {**tool_result, "security_tools": [item for item in tool_result.get("security_tools", []) if item.get("name") != "OSV-Scanner"] + [osv_result]},
        "dependencies": dependency_result, **metadata,
    }
