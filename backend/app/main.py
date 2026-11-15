import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from sqlalchemy import func, select
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.routes.health import router as health_router
from app.api.routes.analysis import router as analysis_router
from app.api.routes.history import router as history_router
from app.api.routes.auth import router as auth_router
from app.api.routes.ops import router as ops_router
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.upload_auth import UploadAuthenticationMiddleware
from app.db.database import SessionLocal
from app.models.analysis_job import AnalysisJob

is_production = settings.app_env.lower() == "production"


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    from app.core.production import validate_production_settings

    validate_production_settings(settings)
    yield


HTTP_REQUESTS = Counter("vulnscan_http_requests_total", "HTTP requests handled by VulnScan.", ["method", "route", "status_code"])
HTTP_REQUEST_DURATION = Histogram("vulnscan_http_request_duration_seconds", "HTTP request latency.", ["method", "route"])
ANALYSIS_JOBS = Gauge("vulnscan_analysis_jobs", "Analysis jobs grouped by state.", ["status"])
METRICS_DB_ERRORS = Counter("vulnscan_metrics_db_collection_errors_total", "Database errors while collecting queue metrics.")

app = FastAPI(
    title="VulnScan Pro API",
    version="0.4.0",
    description="Security auditing foundation. Use only on authorized targets.",
    docs_url=None if is_production else "/docs",
    redoc_url=None if is_production else "/redoc",
    openapi_url=None if is_production else "/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(RateLimitMiddleware)
# Register the upload guard before CORS so CORS wraps and decorates its early errors.
app.add_middleware(UploadAuthenticationMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "X-CSRF-Token"],
)

app.include_router(health_router, prefix="/api")
app.include_router(analysis_router, prefix="/api")
app.include_router(history_router, prefix="/api")
app.include_router(auth_router, prefix="/api")
app.include_router(ops_router, prefix="/api")


@app.middleware("http")
async def collect_http_metrics(request: Request, call_next):
    if request.url.path == "/metrics":
        return await call_next(request)
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        route_obj = request.scope.get("route")
        route = getattr(route_obj, "path", "unmatched")
        HTTP_REQUESTS.labels(request.method, route, "500").inc()
        HTTP_REQUEST_DURATION.labels(request.method, route).observe(time.perf_counter() - started)
        raise
    route_obj = request.scope.get("route")
    route = getattr(route_obj, "path", "unmatched")
    HTTP_REQUESTS.labels(request.method, route, str(response.status_code)).inc()
    HTTP_REQUEST_DURATION.labels(request.method, route).observe(time.perf_counter() - started)
    return response


@app.get("/metrics", include_in_schema=False)
def metrics():
    try:
        with SessionLocal() as db:
            for state in ("queued", "running", "completed", "failed", "dead_letter"):
                count = db.scalar(select(func.count()).select_from(AnalysisJob).where(AnalysisJob.status == state)) or 0
                ANALYSIS_JOBS.labels(state).set(count)
    except Exception:
        METRICS_DB_ERRORS.inc()
        logging.getLogger("vulnscan.metrics").exception("Unable to collect queue metrics.")
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/")
def root():
    return {
        "name": "VulnScan Pro API",
        "version": app.version,
        "docs": None if is_production else "/docs",
    }

