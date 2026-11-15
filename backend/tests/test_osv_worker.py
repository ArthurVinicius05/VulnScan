import io
import zipfile

from app.services.osv_worker import normalize_osv_report, stage_lockfiles


def make_zip(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return buffer.getvalue()


def test_stage_lockfiles_only_accepts_known_names(tmp_path):
    data = make_zip([
        ("project/package-lock.json", '{"lockfileVersion": 3}'),
        ("project/random.json", '{"not": "a lockfile"}'),
        ("../escape/package-lock.json", "{}"),
    ])
    root = tmp_path / "source"
    root.mkdir()
    count = stage_lockfiles(data, root)
    assert count == 1
    assert (root / "project/package-lock.json").exists()
    assert not (root.parent / "escape/package-lock.json").exists()


def test_normalize_osv_report_preserves_ids_aliases_and_advisories():
    report = {"results": [{
        "source": {"path": "/tmp/source/package-lock.json"},
        "packages": [{
            "package": {"name": "demo", "version": "1.2.3", "ecosystem": "npm"},
            "vulnerabilities": [{
                "id": "GHSA-abcd-1234",
                "aliases": ["CVE-2026-12345"],
                "database_specific": {"severity": "HIGH"},
                "summary": "A test vulnerability",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}],
                "references": [{"url": "https://example.com/advisory"}],
            }],
        }],
    }]}
    findings = normalize_osv_report(report)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == "GHSA-abcd-1234"
    assert finding["severity"] == "high"
    assert finding["aliases"] == ["CVE-2026-12345"]
    assert finding["package"]["name"] == "demo"
    assert finding["cvss_vector"] == "CVSS:3.1/AV:N"
    assert finding["references"] == ["https://example.com/advisory"]
