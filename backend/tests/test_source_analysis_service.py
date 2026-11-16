import asyncio
import io
import zipfile

import pytest

from app.services import source_analysis


def make_zip(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return buffer.getvalue()


@pytest.fixture
def isolated_scanners(monkeypatch):
    async def fake_python_scanner(_content):
        return {"status": "completed", "tools": [], "security_tools": [], "findings": [], "coverage": {}}

    async def fake_osv_scanner(_content):
        return {"name": "OSV-Scanner", "status": "disabled", "findings": []}

    monkeypatch.setattr(source_analysis, "scan_python_archive", fake_python_scanner)
    monkeypatch.setattr(source_analysis, "scan_dependencies", fake_osv_scanner)
    monkeypatch.setattr(source_analysis, "inventory_dependency_manifests", lambda _content: {"status": "completed", "manifest_count": 0, "manifests": []})


def test_binary_python_file_is_reported_as_partial_and_score_is_capped(isolated_scanners):
    result = asyncio.run(source_analysis.analyze_source_archive(make_zip([("app.py", b"\x00\x01\x02")]), "binary.zip"))

    assert result["status"] == "partial"
    assert result["coverage"]["heuristics"]["candidate_files"] == 1
    assert result["coverage"]["heuristics"]["files_scanned"] == 0
    assert result["coverage"]["heuristics"]["unreadable_files"] == 1
    assert result["security_score"]["value"] == 70
    assert "no_decodable_source_files" in result["security_score"]["cap_reasons"]


def test_archive_without_eligible_source_files_is_not_scored_as_fully_analyzed(isolated_scanners):
    result = asyncio.run(source_analysis.analyze_source_archive(make_zip([("README.md", "documentation only")]), "docs.zip"))

    assert result["status"] == "partial"
    assert result["coverage"]["heuristics"]["candidate_files"] == 0
    assert result["coverage"]["heuristics"]["files_scanned"] == 0
    assert result["security_score"]["value"] == 70
    assert "no_eligible_source_files" in result["security_score"]["cap_reasons"]
