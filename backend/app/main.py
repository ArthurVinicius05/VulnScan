from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.routes.health import router as health_router
from app.api.routes.analysis import router as analysis_router
from app.api.routes.history import router as history_router
from app.api.routes.auth import router as auth_router

app = FastAPI(
    title="VulnScan Pro API",
    version="0.1.0",
    description="Security auditing foundation. Use only on authorized targets.",
)

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
    return {"name": "VulnScan Pro API", "version": app.version, "docs": "/docs"}
