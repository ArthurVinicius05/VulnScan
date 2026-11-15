from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

MAX_PYTHON_FILES = 50
MAX_TOOL_OUTPUT = 1_000_000
TOOL_TIMEOUT_SECONDS = 15
SECRET_ASSIGNMENT = re.compile(
    r"""(?i)(\b[\w.-]*(?:api[_-]?key|token|secret|password|passwd|credential)[\w.-]*\b\s*[:=]\s*)(["'])([^"'\r\n]+)(\2)"""
)


def _redact_evidence(value: object) -> str:
    text = str(value or "")
    text = SECRET_ASSIGNMENT.sub(lambda match: match.group(1) + match.group(2) + "[REDACTED]" + match.group(4), text)
    return text[:240]


def _safe_python_members(archive: zipfile.ZipFile):
    selected = []
    for info in archive.infolist():
        if info.is_dir() or PurePosixPath(info.filename).suffix.lower() != ".py":
            continue
        path = PurePosixPath(info.filename)
        if path.is_absolute() or "\\" in info.filename or any(part in ("", ".", "..") for part in path.parts):
            continue
        if info.file_size > 512 * 1024:
            continue
        selected.append(info)
        if len(selected) >= MAX_PYTHON_FILES:
            break
    return selected


def _run_json_tool(command: list[str], *, cwd: str) -> tuple[str, dict | list | None]:
    """Run a trusted JSON-producing scanner without buffering unbounded process output."""
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONIOENCODING": "utf-8",
        "HOME": cwd,
        "TMPDIR": cwd,
    }
    # File-backed output avoids buffering unbounded scanner output in worker RAM.
    with tempfile.TemporaryFile(mode="w+b", dir=cwd) as stdout_file, tempfile.TemporaryFile(
        mode="w+b", dir=cwd
    ) as stderr_file:
        try:
            completed = subprocess.run(
                command,
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                timeout=TOOL_TIMEOUT_SECONDS,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            return "timeout", None
        except OSError:
            return "unavailable", None

        if stdout_file.tell() > MAX_TOOL_OUTPUT or stderr_file.tell() > MAX_TOOL_OUTPUT:
            return "output_limit", None
        stdout_file.seek(0)
        output = stdout_file.read(MAX_TOOL_OUTPUT + 1).decode("utf-8", errors="replace")
        try:
            parsed = json.loads(output) if output.strip() else None
        except json.JSONDecodeError:
            return "invalid_output", None

        if completed.returncode not in (0, 1):
            return "error", None
        return "completed", parsed


def run_python_tools(zip_bytes: bytes) -> dict:
    """Run Bandit and Ruff against bounded Python files in a temporary directory."""
    with zipfile.ZipFile(__import__("io").BytesIO(zip_bytes)) as archive:
        eligible_members = [
            info for info in archive.infolist()
            if not info.is_dir()
            and PurePosixPath(info.filename).suffix.lower() == ".py"
            and not PurePosixPath(info.filename).is_absolute()
            and "\\\\" not in info.filename
            and not any(part in ("", ".", "..") for part in PurePosixPath(info.filename).parts)
            and info.file_size <= 512 * 1024
        ]
        members = eligible_members[:MAX_PYTHON_FILES]
        truncated = len(eligible_members) > len(members)
        if not members:
            return {
                "status": "skipped",
                "reason": "No eligible Python files found.",
                "tools": [],
                "findings": [],
            }

        with tempfile.TemporaryDirectory(prefix="vulnscan-") as temp_dir:
            root = Path(temp_dir).resolve()
            written = []
            for info in members:
                target = (root / Path(*PurePosixPath(info.filename).parts)).resolve()
                if not target.is_relative_to(root):
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(info))
                written.append(target)

            if not written:
                return {"status": "skipped", "reason": "No safe Python files to scan.", "tools": [], "findings": []}

            tools = []
            findings = []

            bandit_status, bandit_data = _run_json_tool(
                [sys.executable, "-m", "bandit", "-f", "json", "-q", "-r", str(root)],
                cwd=temp_dir,
            )
            bandit_report_status = "partial" if bandit_status == "completed" and truncated else bandit_status
            tools.append({"name": "Bandit", "status": bandit_report_status, "files_scanned": len(written), "files_available": len(eligible_members)})
            if bandit_status == "completed" and isinstance(bandit_data, dict):
                for item in bandit_data.get("results", []):
                    findings.append({
                        "rule_id": item.get("test_id", "BANDIT"),
                        "title": item.get("test_name", "Bandit finding"),
                        "severity": str(item.get("issue_severity", "medium")).lower(),
                        "confidence": str(item.get("issue_confidence", "medium")).lower(),
                        "file": item.get("filename", "").replace(str(root) + os.sep, ""),
                        "line": item.get("line_number"),
                        "evidence": _redact_evidence(item.get("code", "")),
                        "recommendation": item.get("issue_text", "Review the flagged code."),
                        "verified": False,
                        "source": "Bandit",
                    })

            ruff_executable = shutil.which("ruff")
            if not ruff_executable:
                tools.append({"name": "Ruff", "status": "unavailable", "files_scanned": 0, "files_available": len(eligible_members)})
            else:
                ruff_status, ruff_data = _run_json_tool(
                    [ruff_executable, "check", "--output-format", "json", str(root)],
                    cwd=temp_dir,
                )
                ruff_report_status = "partial" if ruff_status == "completed" and truncated else ruff_status
                tools.append({"name": "Ruff", "status": ruff_report_status, "files_scanned": len(written), "files_available": len(eligible_members)})
                if ruff_status == "completed" and isinstance(ruff_data, list):
                    for item in ruff_data:
                        location = item.get("location") or {}
                        findings.append({
                            "rule_id": item.get("code", "RUFF"),
                            "title": item.get("message", "Code quality finding"),
                            "severity": "informational",
                            "confidence": "high",
                            "file": item.get("filename", "").replace(str(root) + os.sep, ""),
                            "line": location.get("row"),
                            "evidence": "",
                            "recommendation": item.get("message", "Review this code quality issue."),
                            "verified": False,
                            "source": "Ruff",
                            "category": "code_quality",
                        })

            successful = [tool for tool in tools if tool["status"] in {"completed", "partial"}]
            overall = "partial" if truncated or any(tool["status"] not in {"completed", "partial"} for tool in tools) else ("completed" if successful else "unavailable")
            return {
                "status": overall,
                "tools": tools,
                "findings": findings,
                "coverage": {
                    "python_files_available": len(eligible_members),
                    "python_files_scanned": len(written),
                    "python_file_limit": MAX_PYTHON_FILES,
                    "truncated": truncated,
                },
            }
