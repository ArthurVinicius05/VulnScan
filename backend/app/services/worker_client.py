from __future__ import annotations

import httpx

from app.core.config import settings


async def scan_python_archive(content: bytes) -> dict:
    """Send an archive to the private scanner worker; fail closed to an unavailable status."""
    try:
        async with httpx.AsyncClient(timeout=settings.scanner_worker_timeout_seconds) as client:
            response = await client.post(
                f"{settings.scanner_worker_url.rstrip('/')}/scan/python",
                files={"file": ("source.zip", content, "application/zip")},
                headers=(
                    {"Authorization": f"Bearer {settings.scanner_worker_token}"}
                    if settings.scanner_worker_token else {}
                ),
            )
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError("Invalid scanner worker response")
            return payload
    except (httpx.HTTPError, ValueError):
        return {
            "status": "unavailable",
            "reason": "The isolated scanner worker is unavailable or returned an invalid response.",
            "tools": [],
            "findings": [],
        }
