from __future__ import annotations

import io
import json
import re
import zipfile
from pathlib import PurePosixPath

MAX_MANIFEST_BYTES = 256 * 1024
MAX_MANIFESTS = 100

MANIFESTS = {
    "package.json": "npm",
    "package-lock.json": "npm lockfile",
    "yarn.lock": "Yarn",
    "pnpm-lock.yaml": "pnpm",
    "requirements.txt": "pip",
    "pyproject.toml": "Python project",
    "poetry.lock": "Poetry",
    "Pipfile": "Pipenv",
    "Pipfile.lock": "Pipenv lockfile",
    "Cargo.toml": "Cargo",
    "Cargo.lock": "Cargo lockfile",
    "go.mod": "Go modules",
    "go.sum": "Go checksum",
    "Gemfile": "Bundler",
    "Gemfile.lock": "Bundler lockfile",
    "composer.json": "Composer",
    "composer.lock": "Composer lockfile",
    "pom.xml": "Maven",
    "build.gradle": "Gradle",
    "build.gradle.kts": "Gradle Kotlin",
}


def _safe_name(name: str) -> bool:
    path = PurePosixPath(name)
    return bool(name) and not path.is_absolute() and "\\" not in name and not any(
        part in ("", ".", "..") for part in path.parts
    )


def inventory_dependency_manifests(data: bytes) -> dict:
    """Inventory manifests without installing packages or accessing the network."""
    detected = []
    skipped = 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            if not _safe_name(info.filename):
                skipped += 1
                continue
            basename = PurePosixPath(info.filename).name
            ecosystem = MANIFESTS.get(basename)
            if not ecosystem:
                continue
            if info.file_size > MAX_MANIFEST_BYTES:
                detected.append({"file": info.filename, "ecosystem": ecosystem,
                                 "status": "skipped_too_large", "dependency_count": None})
                continue
            try:
                text = archive.read(info).decode("utf-8-sig")
            except (UnicodeDecodeError, OSError, RuntimeError):
                detected.append({"file": info.filename, "ecosystem": ecosystem,
                                 "status": "unreadable", "dependency_count": None})
                continue

            count = None
            if basename == "package.json":
                try:
                    package = json.loads(text)
                    count = sum(
                        len(package.get(section, {}))
                        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
                        if isinstance(package.get(section, {}), dict)
                    )
                except (json.JSONDecodeError, AttributeError):
                    detected.append({"file": info.filename, "ecosystem": ecosystem,
                                     "status": "invalid_manifest", "dependency_count": None})
                    continue
            elif basename == "requirements.txt":
                count = sum(
                    1 for line in text.splitlines()
                    if line.strip() and not line.lstrip().startswith(("#", "-", "http://", "https://"))
                )
            elif basename == "go.mod":
                count = sum(
                    1 for line in text.splitlines()
                    if re.match(r"^\\s*[^/\\s]+\\.[^/\\s]+\\s+\\S+", line)
                )

            detected.append({"file": info.filename, "ecosystem": ecosystem,
                             "status": "inventoried", "dependency_count": count})
            if len(detected) >= MAX_MANIFESTS:
                break

    return {
        "status": "completed",
        "network_access": False,
        "packages_installed": False,
        "manifest_count": len(detected),
        "manifests": detected,
        "skipped_unsafe_paths": skipped,
        "notice": "Manifest inventory only; dependencies were not installed or checked against vulnerability databases.",
    }
