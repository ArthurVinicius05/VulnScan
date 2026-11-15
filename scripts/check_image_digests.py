#!/usr/bin/env python3
"""Verify every Dockerfile/Compose/CI image reference is pinned to images.lock."""
from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "images.lock"
IMAGE_FILES = [
    "backend/Dockerfile",
    "backend/Dockerfile.smtp-proxy",
    "backend/Dockerfile.website",
    "backend/Dockerfile.osv",
    "frontend/Dockerfile",
    "frontend/Dockerfile.production",
    "docker-compose.yml",
    "docker-compose.production.yml",
    ".github/workflows/ci.yml",
]


def load_lock() -> dict[str, str]:
    entries: dict[str, str] = {}
    for raw in LOCK.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        image, digest = line.split()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError(f"Invalid digest for {image}: {digest}")
        entries[image] = digest
    return entries


def image_references() -> list[tuple[str, str, int]]:
    found = []
    for relative in IMAGE_FILES:
        path = ROOT / relative
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            image = None
            if stripped.startswith("FROM "):
                parts = stripped.split()
                image = parts[2] if parts[1].startswith("--platform=") else parts[1]
            elif re.match(r"^image:\s*", stripped):
                image = stripped.split(":", 1)[1].strip().strip('"').strip("'")
            if image and image != "scratch":
                found.append((relative, image, number))
    return found


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-registry", action="store_true")
    args = parser.parse_args()
    lock = load_lock()
    errors = []
    for path, reference, line in image_references():
        if "@sha256:" not in reference:
            errors.append(f"{path}:{line}: image is not digest-pinned: {reference}")
            continue
        image, digest = reference.rsplit("@", 1)
        if lock.get(image) != digest:
            errors.append(f"{path}:{line}: {image} digest does not match images.lock")
    if args.verify_registry:
        for image, expected in lock.items():
            try:
                raw = subprocess.run(
                    ["skopeo", "inspect", "--raw", f"docker://{image}"],
                    check=True, capture_output=True,
                ).stdout
                actual = "sha256:" + hashlib.sha256(raw).hexdigest()
                if actual != expected:
                    errors.append(f"{image}: registry digest changed (expected {expected}, got {actual})")
            except (OSError, subprocess.CalledProcessError) as exc:
                errors.append(f"{image}: unable to verify registry digest: {exc}")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Verified {len(image_references())} pinned image references across {len(lock)} image digests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
