from __future__ import annotations

import json
import os
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from fastapi import FastAPI, File, HTTPException, UploadFile

app = FastAPI(title="VulnScan OSV network worker", docs_url=None, redoc_url=None, openapi_url=None)
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_FILES = 200
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 10 * 1024 * 1024
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
TIMEOUT_SECONDS = 45
ALLOWED_NAMES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "bun.lock", "bun.lockb", "requirements.txt", "poetry.lock", "Pipfile.lock",
    "uv.lock", "pylock.toml", "Cargo.lock", "go.mod", "go.sum", "Gemfile.lock",
    "composer.lock", "pom.xml", "gradle.lockfile", "buildscript-gradle.lockfile",
    "pubspec.lock", "mix.lock", "packages.lock.json", "packages.config",
}


def stage_lockfiles(data: bytes, root: Path) -> int:
    count = total = 0
    with zipfile.ZipFile(__import__("io").BytesIO(data)) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            path = PurePosixPath(info.filename)
            if (not info.filename or path.is_absolute() or "\\\\" in info.filename
                    or any(part in ("", ".", "..") for part in path.parts)):
                continue
            if path.name not in ALLOWED_NAMES:
                continue
            if info.file_size <= 0 or info.file_size > MAX_FILE_BYTES or count >= MAX_FILES:
                continue
            if total + info.file_size > MAX_TOTAL_BYTES:
                break
            try:
                content = archive.read(info)
                content.decode("utf-8")
            except (UnicodeDecodeError, OSError, RuntimeError, zipfile.BadZipFile):
                continue
            target = (root / Path(*path.parts)).resolve()
            if not target.is_relative_to(root):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            count += 1
            total += len(content)
    return count


def normalize_osv_report(report: dict) -> list[dict]:
    findings = []
    for result in report.get("results") or []:
        source = result.get("source") or {}
        source_path = str(source.get("path") or "")[-240:]
        for package_result in result.get("packages") or []:
            package = package_result.get("package") or {}
            name = str(package.get("name") or "unknown")[:180]
            version = str(package.get("version") or "unknown")[:80]
            ecosystem = str(package.get("ecosystem") or "unknown")[:80]
            for vuln in package_result.get("vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                aliases = [str(x)[:80] for x in (vuln.get("aliases") or [])[:20]]
                db = vuln.get("database_specific") or {}
                raw_severity = str(db.get("severity") or "").lower()
                severity = raw_severity if raw_severity in {"critical", "high", "medium", "low", "informational"} else "unknown"
                cvss_vector = None
                for item in vuln.get("severity") or []:
                    score = item.get("score") if isinstance(item, dict) else None
                    if score:
                        cvss_vector = str(score)[:120]
                        break
                summary = str(vuln.get("summary") or db.get("description") or "Known vulnerability reported by OSV.")[:500]
                refs = []
                for ref in (vuln.get("references") or [])[:10]:
                    url = ref.get("url") if isinstance(ref, dict) else None
                    if isinstance(url, str) and url.startswith(("https://", "http://")):
                        refs.append(url[:500])
                findings.append({
                    "rule_id": str(vuln.get("id") or "OSV-UNKNOWN")[:100],
                    "title": f"Vulnerable dependency: {name}",
                    "severity": severity,
                    "confidence": "high",
                    "file": source_path,
                    "line": None,
                    "evidence": f"{ecosystem}:{name}@{version} · aliases: {', '.join(aliases)}"[:500],
                    "recommendation": summary,
                    "verified": False,
                    "source": "OSV-Scanner",
                    "category": "dependency_vulnerability",
                    "package": {"name": name, "version": version, "ecosystem": ecosystem},
                    "aliases": aliases,
                    "references": refs,
                    "cvss_vector": cvss_vector,
                })
                if len(findings) >= 500:
                    return findings
    return findings


@app.get("/health")
def health():
    return {"status": "ok", "service": "osv-worker"}


@app.post("/scan")
async def scan(file: UploadFile = File(...)):
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Archive exceeds OSV worker limit.")
    try:
        with tempfile.TemporaryDirectory(prefix="vulnscan-osv-") as temp:
            root = Path(temp).resolve() / "source"
            root.mkdir()
            count = stage_lockfiles(content, root)
            if not count:
                return {"status": "skipped", "reason": "No supported dependency lockfiles found.", "findings": []}
            stdout_path = Path(temp) / "osv-output.json"
            stderr_path = Path(temp) / "osv-error.log"
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                try:
                    proc = subprocess.run(
                        ["osv-scanner", "scan", "source", "--recursive", "--format", "json", "--verbosity", "error", str(root)],
                        cwd=temp, env={"PATH": os.environ.get("PATH", ""), "HOME": temp, "TMPDIR": temp},
                        stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                        timeout=TIMEOUT_SECONDS, check=False, shell=False,
                    )
                except subprocess.TimeoutExpired:
                    return {"status": "timeout", "findings": []}
            if stdout_path.stat().st_size > MAX_OUTPUT_BYTES or stderr_path.stat().st_size > MAX_OUTPUT_BYTES:
                return {"status": "output_limit", "findings": []}
            if proc.returncode not in (0, 1):
                return {"status": "error", "findings": []}
            try:
                report = json.loads(stdout_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError, UnicodeDecodeError):
                return {"status": "invalid_output", "findings": []}
            findings = normalize_osv_report(report) if isinstance(report, dict) else []
            return {"status": "completed", "findings": findings, "lockfiles_scanned": count}
    except (zipfile.BadZipFile, OSError, ValueError):
        raise HTTPException(status_code=400, detail="Archive could not be scanned.")
