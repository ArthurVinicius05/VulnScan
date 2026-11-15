from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.routes.health import router as health_router
from app.api.routes.analysis import router as analysis_router
from app.api.routes.history import router as history_router
from app.api.routes.auth import router as auth_router
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.upload_auth import UploadAuthenticationMiddleware

is_production = settings.app_env.lower() == "production"

app = FastAPI(
    title="VulnScan Pro API",
    version="0.4.0",
    description="Security auditing foundation. Use only on authorized targets.",
    docs_url=None if is_production else "/docs",
    redoc_url=None if is_production else "/redoc",
    openapi_url=None if is_production else "/openapi.json",
)

app.add_middleware(RateLimitMiddleware)
# Register the upload guard before CORS so CORS wraps and decorates its early errors.
app.add_middleware(UploadAuthenticationMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-CSRF-Token"],
)

app.include_router(health_router, prefix="/api")
app.include_router(analysis_router, prefix="/api")
app.include_router(history_router, prefix="/api")
app.include_router(auth_router, prefix="/api")


@app.get("/")
def root():
    return {
        "name": "VulnScan Pro API",
        "version": app.version,
        "docs": None if is_production else "/docs",
    }
