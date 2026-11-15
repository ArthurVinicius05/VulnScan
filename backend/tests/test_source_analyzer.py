import io
import zipfile

from app.services.source_analyzer import analyze_source_zip


def make_zip(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return buffer.getvalue()


def test_detects_dynamic_execution():
    data = make_zip([("app.py", "user_input = input()\\neval(user_input)\\n")])
    findings = analyze_source_zip(data)
    assert any(item["rule_id"] == "PY001" and item["line"] == 2 for item in findings)


def test_detects_possible_secret():
    data = make_zip([("settings.py", 'API_KEY = "abc1234567890abcdef"\\n')])
    findings = analyze_source_zip(data)
    secret = next(item for item in findings if item["rule_id"] == "SECRET001")
    assert "abc1234567890abcdef" not in secret["evidence"]
    assert "[REDACTED]" in secret["evidence"]


def test_ignores_non_source_files():
    data = make_zip([("notes.txt", "eval(user_input)")])
    assert analyze_source_zip(data) == []


def test_marks_heuristic_findings_as_unverified():
    data = make_zip([("page.js", "element.innerHTML = value")])
    findings = analyze_source_zip(data)
    assert findings and findings[0]["verified"] is False


def test_scans_dot_env_files_for_credentials():
    data = make_zip([(".env", 'API_KEY="abc1234567890abcdef"\\n')])
    findings = analyze_source_zip(data)
    assert any(item["rule_id"] == "SECRET001" and item["file"] == ".env" for item in findings)


def test_secret_is_redacted_before_evidence_is_truncated():
    secret = "super-secret-value-that-must-never-appear"
    line = "DB_PASSWORD = \"" + secret + "\""
    data = make_zip([("config.py", " " * 260 + line + "\\n")])
    findings = analyze_source_zip(data)
    finding = next(item for item in findings if item["rule_id"] == "SECRET001")
    assert secret not in finding["evidence"]
    assert "[REDACTED]" in finding["evidence"]


def test_long_lines_are_bounded_and_do_not_crash():
    data = make_zip([("app.py", "x" * 200_000 + "\\neval(user_input)\\n")])
    findings = analyze_source_zip(data)
    assert any(item["rule_id"] == "PY001" for item in findings)
