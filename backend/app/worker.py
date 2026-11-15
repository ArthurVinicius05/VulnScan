from fastapi import FastAPI, File, HTTPException, UploadFile

from app.services.scanner_integrations import run_python_tools

app = FastAPI(
    title="VulnScan isolated scanner worker",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

MAX_UPLOAD_BYTES = 25 * 1024 * 1024


@app.get("/health")
def health():
    return {"status": "ok", "service": "scanner-worker"}


@app.post("/scan/python")
async def scan_python(file: UploadFile = File(...)):
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Archive exceeds worker limit.")

    try:
        return run_python_tools(content)
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail="Archive could not be scanned.") from exc
