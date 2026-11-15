from __future__ import annotations

import io
import re
import zipfile
from pathlib import PurePosixPath

TEXT_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".php", ".rb",
    ".go", ".rs", ".yml", ".yaml", ".json", ".toml", ".env",
    ".sh", ".sql", ".html", ".htm",
}
MAX_FILE_BYTES = 512 * 1024
MAX_TOTAL_SOURCE_BYTES = 5 * 1024 * 1024

RULES = [
    {
        "id": "SECRET001",
        "title": "Possible hardcoded credential",
        "severity": "high",
        "confidence": "medium",
        "pattern": re.compile(
            r"""(?i)\b(?:api[_-]?key|secret|password|passwd|access[_-]?token)\b\s*[:=]\s*["']([^"'\s]{16,})["']"""
        ),
        "recommendation": "Move the value to a secret manager or environment variable, rotate it if real, and ensure it is not committed.",
    },
    {
        "id": "PY001",
        "title": "Dynamic code execution",
        "severity": "high",
        "confidence": "high",
        "extensions": {".py"},
        "pattern": re.compile(r"\b(?:eval|exec)\s*\("),
        "recommendation": "Avoid evaluating dynamic input. Replace it with explicit parsing or a strict allowlist of permitted operations.",
    },
    {
        "id": "PY002",
        "title": "Subprocess with shell enabled",
        "severity": "high",
        "confidence": "high",
        "extensions": {".py"},
        "pattern": re.compile(r"\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\([^\n]*\bshell\s*=\s*True"),
        "recommendation": "Prefer argument arrays with shell=False. Validate arguments and never concatenate untrusted input into a command.",
    },
    {
        "id": "PY003",
        "title": "Unsafe pickle deserialization",
        "severity": "high",
        "confidence": "high",
        "extensions": {".py"},
        "pattern": re.compile(r"\bpickle\.(?:loads?|Unpickler)\b"),
        "recommendation": "Do not deserialize pickle data from untrusted sources. Use a non-executable data format such as JSON.",
    },
    {
        "id": "PY004",
        "title": "Potentially unsafe YAML loading",
        "severity": "medium",
        "confidence": "medium",
        "extensions": {".py"},
        "pattern": re.compile(r"\byaml\.load\s*\("),
        "recommendation": "Use yaml.safe_load for untrusted YAML, and validate the resulting data against an expected schema.",
    },
    {
        "id": "WEB001",
        "title": "Direct HTML injection sink",
        "severity": "medium",
        "confidence": "medium",
        "extensions": {".js", ".jsx", ".ts", ".tsx"},
        "pattern": re.compile(r"\b(?:innerHTML|outerHTML)\s*="),
        "recommendation": "Avoid assigning untrusted strings to HTML injection sinks. Prefer textContent or framework-safe rendering; sanitize only when HTML is required.",
    },
    {
        "id": "SQL001",
        "title": "Possible SQL built through string formatting",
        "severity": "medium",
        "confidence": "low",
        "extensions": {".py", ".js", ".ts", ".java", ".php"},
        "pattern": re.compile(r"(?i)(?:execute|query)\s*\(\s*(?:f["']|["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*\+)"),
        "recommendation": "Use parameterized queries or prepared statements. This pattern is heuristic and requires manual verification.",
    },
]

PLACEHOLDER_VALUES = {
    "your_api_key", "changeme", "replace_me", "example", "xxxxxxxx",
    "your_secret", "password", "secret", "test",
}


def analyze_source_zip(data: bytes) -> list[dict]:
    """Run bounded, read-only heuristic checks on text files in a ZIP archive."""
    findings: list[dict] = []
    scanned_bytes = 0

    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            suffix = PurePosixPath(info.filename).suffix.lower()
            if suffix not in TEXT_EXTENSIONS or info.file_size > MAX_FILE_BYTES:
                continue
            if scanned_bytes + info.file_size > MAX_TOTAL_SOURCE_BYTES:
                break

            raw = archive.read(info)
            scanned_bytes += len(raw)
            if b"\x00" in raw:
                continue
            try:
                source = raw.decode("utf-8-sig")
            except UnicodeDecodeError:
                continue

            for line_number, line in enumerate(source.splitlines(), start=1):
                for rule in RULES:
                    allowed = rule.get("extensions")
                    if allowed and suffix not in allowed:
                        continue
                    match = rule["pattern"].search(line)
                    if not match:
                        continue
                    if rule["id"] == "SECRET001":
                        value = match.group(1).strip().lower()
                        if value in PLACEHOLDER_VALUES or value.startswith(("your_", "example_", "changeme")):
                            continue
                    findings.append({
                        "rule_id": rule["id"],
                        "title": rule["title"],
                        "severity": rule["severity"],
                        "confidence": rule["confidence"],
                        "file": info.filename,
                        "line": line_number,
                        "evidence": line.strip()[:240],
                        "recommendation": rule["recommendation"],
                        "verified": False,
                    })
                    if len(findings) >= 200:
                        return findings

    return findings
