from __future__ import annotations

import httpx

from app.core.config import settings


async def scan_website_target(url: str, *, authorized: bool) -> dict:
    if not settings.enable_website_scan:
        return {"status": "disabled", "findings": [], "reason": "Ative ENABLE_WEBSITE_SCAN e o perfil website-scan."}
    try:
        async with httpx.AsyncClient(timeout=settings.website_worker_timeout_seconds) as client:
            response = await client.post(
                f"{settings.website_worker_url.rstrip('/')}/scan",
                json={"url": url, "authorized": authorized},
            )
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError("Resposta inválida do worker")
            return payload
    except httpx.HTTPStatusError as exc:
        try:
            detail = exc.response.json().get("detail", "O worker recusou a verificação.")
        except ValueError:
            detail = "O worker recusou a verificação."
        raise ValueError(str(detail)) from exc
    except (httpx.HTTPError, ValueError):
        return {"status": "unavailable", "findings": [], "reason": "O worker de sites está indisponível."}
