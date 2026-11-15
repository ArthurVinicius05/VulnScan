from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

MAX_FILES = 200
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 10 * 1024 * 1024
MAX_REPORT_BYTES = 2 * 1024 * 1024
TIMEOUT_SECONDS = 20

TEXT_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yaml", ".yml", ".toml",
    ".ini", ".cfg", ".conf", ".env", ".properties", ".xml", ".html", ".css",
    ".sh", ".bash", ".go", ".rs", ".java", ".kt", ".rb", ".php", ".sql",
    ".md", ".txt", ".lock", ".gradle", ".gitignore",
}
MANIFEST_NAMES = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile",
    "Pipfile.lock", "Cargo.toml", "Cargo.lock", "go.mod", "go.sum",
    "Gemfile", "Gemfile.lock", "composer.json", "composer.lock",
    "pom.xml", "build.gradle", "build.gradle.kts",
}


def _safe_member(name: str) -> bool:
    path = PurePosixPath(name)
    return bool(name) and not path.is_absolute() and "\\" not in name and not any(
        part in ("", ".", "..") for part in path.parts
    )


def _stage_text_files(archive: zipfile.ZipFile, root: Path) -> tuple[int, int]:
    count = total = 0
    for info in archive.infolist():
        if info.is_dir() or not _safe_member(info.filename):
            continue
        path = PurePosixPath(info.filename)
        if (
            path.suffix.lower() not in TEXT_SUFFIXES
            and path.name not in MANIFEST_NAMES
            and not path.name.startswith(".env")
        ):
            continue
        if info.file_size > MAX_FILE_BYTES or count >= MAX_FILES:
            continue
        if total + info.file_size > MAX_TOTAL_BYTES:
            break
        target = (root / Path(*path.parts)).resolve()
        if not target.is_relative_to(root):
            continue
        try:
            raw = archive.read(info)
            raw.decode("utf-8")
        except (UnicodeDecodeError, OSError, RuntimeError, zipfile.BadZipFile):
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        count += 1
        total += len(raw)
    return count, total


def run_gitleaks(zip_bytes: bytes) -> dict:
    """Run Gitleaks on bounded text files; uploaded project code is never executed."""
    executable = shutil.which("gitleaks")
    if not executable:
        return {"name": "Gitleaks", "status": "unavailable", "findings": []}

    try:
        with zipfile.ZipFile(__import__("io").BytesIO(zip_bytes)) as archive:
            with tempfile.TemporaryDirectory(prefix="vulnscan-secrets-") as temp_dir:
                root = Path(temp_dir).resolve() / "source"
                root.mkdir()
                file_count, _ = _stage_text_files(archive, root)
                if not file_count:
                    return {"name": "Gitleaks", "status": "skipped", "findings": []}

                report = Path(temp_dir) / "gitleaks-report.json"
                env = {
                    "PATH": os.environ.get("PATH", ""),
                    "HOME": temp_dir,
                    "TMPDIR": temp_dir,
                }
                try:
                    completed = subprocess.run(
                        [
                            executable, "detect", "--source", str(root), "--no-git",
                            "--report-format", "json", "--report-path", str(report),
                            "--exit-code", "0", "--no-banner",
                        ],
                        cwd=temp_dir,
                        env=env,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=TIMEOUT_SECONDS,
                        check=False,
                        shell=False,
                    )
                except subprocess.TimeoutExpired:
                    return {"name": "Gitleaks", "status": "timeout", "findings": []}
                except OSError:
                    return {"name": "Gitleaks", "status": "unavailable", "findings": []}

                if completed.returncode != 0:
                    return {"name": "Gitleaks", "status": "error", "findings": []}
                if not report.exists() or report.stat().st_size > MAX_REPORT_BYTES:
                    return {"name": "Gitleaks", "status": "invalid_output", "findings": []}

                try:
                    raw_findings = json.loads(report.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError, UnicodeDecodeError):
                    return {"name": "Gitleaks", "status": "invalid_output", "findings": []}

                findings = []
                if isinstance(raw_findings, list):
                    for item in raw_findings[:200]:
                        if not isinstance(item, dict):
                            continue
                        findings.append({
                            "rule_id": "GITLEAKS_" + str(item.get("RuleID", "SECRET")).upper()[:64],
                            "title": "Potential exposed secret",
                            "severity": "high",
                            "confidence": "high",
                            "file": str(item.get("File", ""))[:240],
                            "line": item.get("StartLine"),
                            "evidence": "[REDACTED] Secret value withheld.",
                            "recommendation": "Revoke or rotate the exposed credential and remove it from source history.",
                            "verified": False,
                            "source": "Gitleaks",
                            "category": "secret",
                        })
                return {"name": "Gitleaks", "status": "completed", "findings": findings}
    except (zipfile.BadZipFile, OSError, ValueError):
        return {"name": "Gitleaks", "status": "error", "findings": []}


def osv_scanner_status() -> dict:
    """OSV is deliberately disabled until a separately approved network policy exists."""
    return {
        "name": "OSV-Scanner",
        "status": "disabled",
        "findings": [],
        "reason": "Dependency vulnerability matching is disabled by default; no outbound network access is granted to the scanner worker.",
    }


def run_security_tools(zip_bytes: bytes) -> dict:
    gitleaks = run_gitleaks(zip_bytes)
    osv = osv_scanner_status()
    return {
        "tools": [gitleaks, osv],
        "findings": gitleaks["findings"] + osv["findings"],
    }
