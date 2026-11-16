from __future__ import annotations

from collections import Counter
from typing import Any

SCORING_MODEL_VERSION = "1.1"
SEVERITY_PENALTIES = {
    "critical": 30.0,
    "high": 15.0,
    "medium": 7.0,
    "low": 2.5,
    "informational": 0.5,
    "unknown": 2.0,
}
CONFIDENCE_FACTORS = {"high": 1.0, "medium": 0.75, "low": 0.5}


def calculate_security_score(
    findings: list[dict[str, Any]],
    *,
    analysis_status: str,
    coverage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Deterministic prioritization indicator, not a security certification."""
    severity_counts: Counter[str] = Counter()
    deductions: Counter[str] = Counter()
    total_penalty = 0.0

    for finding in findings:
        severity = str(finding.get("severity", "unknown")).lower()
        confidence = str(finding.get("confidence", "unknown")).lower()
        penalty = SEVERITY_PENALTIES.get(severity, 0.0) * CONFIDENCE_FACTORS.get(confidence, 0.5)
        if penalty > 0:
            severity_counts[severity] += 1
            deductions[severity] += penalty
            total_penalty += penalty

    raw_score = max(0, min(100, round(100 - min(100.0, total_penalty))))
    score_cap = 100
    cap_reasons: list[str] = []
    coverage_data = coverage or {}
    heuristic_coverage = coverage_data.get("heuristics") or {}

    if heuristic_coverage.get("candidate_files") == 0:
        score_cap = min(score_cap, 70)
        cap_reasons.append("no_eligible_source_files")
    elif heuristic_coverage.get("files_scanned") == 0:
        score_cap = min(score_cap, 70)
        cap_reasons.append("no_decodable_source_files")
    if analysis_status != "completed":
        score_cap = min(score_cap, 85)
        cap_reasons.append("analysis_not_fully_completed")
    if (
        heuristic_coverage.get("files_over_file_limit", 0) > 0
        or heuristic_coverage.get("files_over_total_limit", 0) > 0
        or heuristic_coverage.get("possibly_truncated_by_finding_limit", False)
    ):
        score_cap = min(score_cap, 80)
        cap_reasons.append("heuristic_scan_was_limited")
    if (coverage_data.get("python_tools") or {}).get("truncated") is True:
        score_cap = min(score_cap, 80)
        cap_reasons.append("python_scanner_was_truncated")

    score = min(raw_score, score_cap)
    rating = (
        "strong" if score >= 90 else
        "good" if score >= 75 else
        "needs_attention" if score >= 50 else
        "high_risk"
    )
    return {
        "value": score,
        "rating": rating,
        "model_version": SCORING_MODEL_VERSION,
        "raw_value": raw_score,
        "score_cap": score_cap,
        "is_capped": score < raw_score,
        "cap_reasons": cap_reasons,
        "confidence": "limited" if cap_reasons else "standard",
        "finding_count": len(findings),
        "severity_counts": dict(sorted(severity_counts.items())),
        "deductions": {key: round(value, 2) for key, value in sorted(deductions.items())},
        "methodology": "severity_weighted_confidence_adjusted_v1_1",
        "disclaimer": (
            "A prioritization indicator only; it is not a certification, "
            "a penetration test, or proof that no vulnerabilities exist."
        ),
    }
