from collections import Counter

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
    response: Response,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
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


def _finding_fingerprint(finding: dict) -> str | None:
    rule_id = str(finding.get("rule_id") or finding.get("id") or "").strip().lower()
    package = finding.get("package") if isinstance(finding.get("package"), dict) else {}
    aliases = finding.get("aliases") if isinstance(finding.get("aliases"), list) else []
    stable_aliases = sorted(str(alias).strip().lower() for alias in aliases if alias)
    if stable_aliases:
        identity = "|".join(stable_aliases)
    elif package.get("name"):
        identity = "|".join((rule_id, str(package.get("ecosystem", "")).lower(),
                             str(package.get("name", "")).lower()))
    else:
        location = str(finding.get("file") or finding.get("url") or "").strip().lower()
        title = str(finding.get("title") or "").strip().lower()
        if not rule_id and not location and not title:
            return None
        identity = "|".join((rule_id, location, title))
    return identity




MAX_FINDING_DIFF_ITEMS = 50


def _finding_summary(finding: dict) -> dict:
    """Return a bounded display summary; never include evidence or source snippets."""
    summary = {}
    for key in ("rule_id", "title", "severity", "confidence", "file", "url"):
        value = finding.get(key)
        if value is not None and str(value).strip():
            summary[key] = str(value)[:512]
    package = finding.get("package")
    if isinstance(package, dict) and package.get("name"):
        summary["package"] = {
            "name": str(package.get("name", ""))[:256],
            "version": str(package.get("version", ""))[:128],
            "ecosystem": str(package.get("ecosystem", ""))[:128],
        }
    aliases = finding.get("aliases")
    if isinstance(aliases, list):
        summary["aliases"] = [str(alias)[:128] for alias in aliases[:10] if alias]
    return summary


def _finding_index(result: dict) -> tuple[dict[str, list[dict]], Counter]:
    indexed: dict[str, list[dict]] = {}
    severities: Counter = Counter()
    findings = result.get("findings")
    if not isinstance(findings, list):
        return indexed, severities
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        fingerprint = _finding_fingerprint(finding)
        if fingerprint:
            indexed.setdefault(fingerprint, []).append(_finding_summary(finding))
            severities[str(finding.get("severity") or "unknown").lower()] += 1
    return indexed, severities


@router.get("/compare/{baseline_id}/{candidate_id}")
def compare_audits(
    baseline_id: str,
    candidate_id: str,
    response: Response,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _set_private_no_store(response)
    if baseline_id == candidate_id:
        raise HTTPException(status_code=422, detail="Selecione duas auditorias diferentes.")
    records = db.scalars(select(AuditRecord).where(
        AuditRecord.id.in_([baseline_id, candidate_id]), AuditRecord.user_id == user.id
    )).all()
    by_id = {record.id: record for record in records}
    baseline = by_id.get(baseline_id)
    candidate = by_id.get(candidate_id)
    if baseline is None or candidate is None:
        raise HTTPException(status_code=404, detail="Auditoria não encontrada.")
    if baseline.analysis_type != candidate.analysis_type:
        raise HTTPException(status_code=422, detail="Só é possível comparar auditorias do mesmo tipo.")

    baseline_findings, baseline_severities = _finding_index(baseline.result or {})
    candidate_findings, candidate_severities = _finding_index(candidate.result or {})
    added_findings = []
    resolved_findings = []
    unchanged = 0
    for fingerprint in sorted(set(baseline_findings) | set(candidate_findings)):
        before = baseline_findings.get(fingerprint, [])
        after = candidate_findings.get(fingerprint, [])
        unchanged += min(len(before), len(after))
        if len(after) > len(before):
            added_findings.extend(after[len(before):])
        elif len(before) > len(after):
            resolved_findings.extend(before[len(after):])
    severity_names = sorted(set(baseline_severities) | set(candidate_severities))
    severity_delta = {
        severity: {
            "baseline": baseline_severities.get(severity, 0),
            "candidate": candidate_severities.get(severity, 0),
            "delta": candidate_severities.get(severity, 0) - baseline_severities.get(severity, 0),
        }
        for severity in severity_names
    }
    baseline_score = (baseline.result or {}).get("security_score")
    candidate_score = (candidate.result or {}).get("security_score")
    score_comparable = (
        isinstance(baseline_score, dict) and isinstance(candidate_score, dict)
        and baseline_score.get("model_version") == candidate_score.get("model_version")
        and isinstance(baseline_score.get("value"), (int, float))
        and isinstance(candidate_score.get("value"), (int, float))
    )
    return {
        "baseline": {"id": baseline.id, "target": baseline.target, "created_at": baseline.created_at.isoformat()},
        "candidate": {"id": candidate.id, "target": candidate.target, "created_at": candidate.created_at.isoformat()},
        "findings": {
            "details_available": isinstance((baseline.result or {}).get("findings"), list) and isinstance((candidate.result or {}).get("findings"), list),
            "added": sum(added.values()), "resolved": sum(resolved.values()),
            "unchanged": unchanged, "baseline_total": sum(len(items) for items in baseline_findings.values()),
            "candidate_total": sum(len(items) for items in candidate_findings.values()),
        },
        "finding_diffs": {
            "added": added_findings[:MAX_FINDING_DIFF_ITEMS],
            "resolved": resolved_findings[:MAX_FINDING_DIFF_ITEMS],
            "added_omitted": max(0, len(added_findings) - MAX_FINDING_DIFF_ITEMS),
            "resolved_omitted": max(0, len(resolved_findings) - MAX_FINDING_DIFF_ITEMS),
        },
        "severity_delta": severity_delta,
        "score": {
            "comparable": score_comparable,
            "baseline": baseline_score.get("value") if score_comparable else None,
            "candidate": candidate_score.get("value") if score_comparable else None,
            "delta": candidate_score.get("value") - baseline_score.get("value") if score_comparable else None,
            "model_version": baseline_score.get("model_version") if score_comparable else None,
        },
    }


@router.get("/{audit_id}")
def get_audit(audit_id: str, response: Response, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    _set_private_no_store(response)
    record = db.scalar(select(AuditRecord).where(AuditRecord.id == audit_id, AuditRecord.user_id == user.id))
    if record is None:
        response.status_code = 404
        return {"detail": "Análise não encontrada."}
    return {"id": record.id, "analysis_type": record.analysis_type, "target": record.target,
        "status": record.status, "finding_count": record.finding_count,
        "created_at": record.created_at.isoformat(), "result": record.result}
