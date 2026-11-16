import json

from app.services import security_tool_integrations as integrations


def test_osv_scanner_is_disabled_without_network_policy():
    result = integrations.osv_scanner_status()
    assert result["status"] == "disabled"
    assert result["findings"] == []
    assert "no outbound network" in result["reason"]


def test_gitleaks_reports_unavailable_when_binary_is_missing(monkeypatch):
    monkeypatch.setattr(integrations.shutil, "which", lambda name: None)
    result = integrations.run_gitleaks(b"not-a-zip")
    assert result["name"] == "Gitleaks"
    assert result["status"] == "unavailable"
    assert result["findings"] == []


def test_gitleaks_redacts_secret_evidence(monkeypatch):
    import io
    import zipfile

    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, "w") as archive:
        archive.writestr("config/.env", "API_TOKEN=example-secret-value")

    monkeypatch.setattr(integrations.shutil, "which", lambda name: "/usr/bin/gitleaks")

    def fake_run(command, **kwargs):
        report_path = command[command.index("--report-path") + 1]
        with open(report_path, "w", encoding="utf-8") as report:
            json.dump([{
                "RuleID": "generic-api-key",
                "File": "config/.env",
                "StartLine": 1,
                "Secret": "example-secret-value",
            }], report)

        class Completed:
            returncode = 0

        return Completed()

    monkeypatch.setattr(integrations.subprocess, "run", fake_run)
    result = integrations.run_gitleaks(archive_buffer.getvalue())
    assert result["status"] == "completed"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["evidence"] == "[REDACTED] Secret value withheld."
    assert "example-secret-value" not in str(result)


def test_gitleaks_reports_partial_when_file_limit_truncates_archive(monkeypatch):
    import io
    import zipfile

    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, "w") as archive:
        for index in range(integrations.MAX_FILES + 1):
            archive.writestr(f"src/file_{index}.txt", "safe text")

    monkeypatch.setattr(integrations.shutil, "which", lambda name: "/usr/bin/gitleaks")

    def fake_run(command, **kwargs):
        report_path = command[command.index("--report-path") + 1]
        with open(report_path, "w", encoding="utf-8") as report:
            json.dump([], report)

        class Completed:
            returncode = 0

        return Completed()

    monkeypatch.setattr(integrations.subprocess, "run", fake_run)
    result = integrations.run_gitleaks(archive_buffer.getvalue())

    assert result["status"] == "partial"
    assert result["coverage"]["files_scanned"] == integrations.MAX_FILES
    assert result["coverage"]["truncated"] is True
