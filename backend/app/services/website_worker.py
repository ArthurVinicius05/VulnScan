from __future__ import annotations

import asyncio

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from app.services.target_validation import TargetValidationError
from app.services.website_scanner import scan_website

app = FastAPI(title="VulnScan website worker", docs_url=None, redoc_url=None, openapi_url=None)
_scan_slots = asyncio.Semaphore(4)


class WebsiteScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    authorized: bool


@app.get("/health")
def health():
    return {"status": "ok", "service": "website-worker"}


@app.post("/scan")
async def scan(request: WebsiteScanRequest):
    if request.authorized is not True:
        raise HTTPException(status_code=403, detail="Confirme que possui autorização para avaliar este alvo.")
    if _scan_slots.locked():
        raise HTTPException(status_code=429, detail="Limite de verificações simultâneas atingido.")
    async with _scan_slots:
        try:
            return await run_in_threadpool(scan_website, request.url)
        except TargetValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail="Não foi possível concluir a conexão com o alvo validado.") from exc
