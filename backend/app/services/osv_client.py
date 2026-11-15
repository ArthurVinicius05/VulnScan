from __future__ import annotations

import httpx

from app.core.config import settings


async def scan_dependencies(content: bytes) -> dict:
    if not settings.enable_osv_scan:
        return {"name": "OSV-Scanner", "status": "disabled", "findings": [],
                "reason": "Enable the optional osv-online Compose profile and ENABLE_OSV_SCAN=true to query OSV.dev."}
    try:
        async with httpx.AsyncClient(timeout=settings.osv_worker_timeout_seconds) as client:
            response = await client.post(
                f"{settings.osv_worker_url.rstrip('/')}/scan",
                files={"file": ("source.zip", content, "application/zip")},
            )
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError("Invalid OSV worker response")
            return {"name": "OSV-Scanner", **payload}
    except (httpx.HTTPError, ValueError):
        return {"name": "OSV-Scanner", "status": "unavailable", "findings": [],
                "reason": "The optional OSV worker is unavailable or returned an invalid response."}
