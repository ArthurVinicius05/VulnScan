from hmac import compare_digest

from fastapi import FastAPI, File, Header, HTTPException, UploadFile

from app.core.config import settings
from app.services.scanner_integrations import run_python_tools
from app.services.security_tool_integrations import run_security_tools

app = FastAPI(
    title="VulnScan isolated scanner worker",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

MAX_UPLOAD_BYTES = 25 * 1024 * 1024


def verify_worker_authorization(authorization: str | None) -> None:
    expected = settings.scanner_worker_token
    if settings.app_env.lower() == "production" and not expected:
        raise HTTPException(status_code=503, detail="Scanner worker authentication is not configured.")
    if expected is None:
        return
    supplied = authorization or ""
    if not compare_digest(supplied, f"Bearer {expected}"):
        raise HTTPException(status_code=401, detail="Worker authentication required.")


@app.get("/health")
def health():
    return {"status": "ok", "service": "scanner-worker"}


@app.post("/scan/python")
async def scan_python(
    file: UploadFile = File(...),
    authorization: str | None = Header(default=None),
):
    verify_worker_authorization(authorization)
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Archive exceeds worker limit.")

    try:
        python_result = run_python_tools(content)
        security_result = run_security_tools(content)
        return {
            **python_result,
            "findings": python_result.get("findings", []) + security_result["findings"],
            "security_tools": security_result["tools"],
        }
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail="Archive could not be scanned.") from exc
