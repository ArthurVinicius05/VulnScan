from app.services.security_score import calculate_security_score


def test_empty_complete_analysis_can_score_one_hundred():
    score = calculate_security_score([], analysis_status="completed", coverage={})
    assert score["value"] == 100
    assert score["confidence"] == "standard"
    assert score["is_capped"] is False


def test_severity_and_confidence_change_score_deterministically():
    findings = [
        {"severity": "high", "confidence": "high"},
        {"severity": "medium", "confidence": "low"},
    ]
    score = calculate_security_score(findings, analysis_status="completed")
    assert score["value"] == 82
    assert score["deductions"] == {"high": 15.0, "medium": 3.5}
    assert score["model_version"] == "1.0"


def test_partial_analysis_caps_score_below_perfect():
    score = calculate_security_score([], analysis_status="partial", coverage={})
    assert score["value"] == 85
    assert score["is_capped"] is True
    assert "analysis_not_fully_completed" in score["cap_reasons"]


def test_heuristic_coverage_limits_apply_stricter_cap():
    score = calculate_security_score(
        [],
        analysis_status="completed",
        coverage={"heuristics": {"files_over_file_limit": 1}},
    )
    assert score["value"] == 80
    assert score["score_cap"] == 80
    assert score["confidence"] == "limited"


def test_findings_cannot_reduce_score_below_zero():
    findings = [{"severity": "critical", "confidence": "high"} for _ in range(8)]
    score = calculate_security_score(findings, analysis_status="completed")
    assert score["value"] == 0
    assert score["raw_value"] == 0


def test_no_eligible_source_files_prevents_perfect_score():
    score = calculate_security_score(
        [],
        analysis_status="completed",
        coverage={"heuristics": {"candidate_files": 0}},
    )
    assert score["value"] == 70
    assert "no_eligible_source_files" in score["cap_reasons"]


def test_unknown_severity_is_not_silently_ignored():
    score = calculate_security_score(
        [{"severity": "unknown", "confidence": "low"}],
        analysis_status="completed",
    )
    assert score["value"] == 99
    assert score["severity_counts"] == {"unknown": 1}



def test_no_decodable_source_files_caps_score():
    score = calculate_security_score(
        [],
        analysis_status="partial",
        coverage={"heuristics": {"candidate_files": 1, "files_scanned": 0, "unreadable_files": 1}},
    )
    assert score["value"] == 70
    assert "no_decodable_source_files" in score["cap_reasons"]
