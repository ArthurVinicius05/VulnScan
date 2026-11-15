from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.config import settings
from app.middleware.rate_limit import RateLimitMiddleware


def make_client():
    application = FastAPI()
    application.add_middleware(RateLimitMiddleware)

    @application.post("/api/auth/login")
    def login():
        return {"ok": True}

    @application.post("/api/analysis/website")
    def analyze():
        return {"ok": True}

    @application.get("/health")
    def health():
        return {"ok": True}

    return TestClient(application)


def test_auth_limit_returns_429_and_retry_after(monkeypatch):
    monkeypatch.setattr(settings, "redis_url", None)
    monkeypatch.setattr(settings, "app_env", "development")
    client = make_client()

    for _ in range(10):
        assert client.post("/api/auth/login").status_code == 200

    limited = client.post("/api/auth/login")
    assert limited.status_code == 429
    assert limited.headers["retry-after"] == "300"


def test_analysis_has_separate_limit(monkeypatch):
    monkeypatch.setattr(settings, "redis_url", None)
    monkeypatch.setattr(settings, "app_env", "development")
    client = make_client()

    for _ in range(5):
        assert client.post("/api/analysis/website").status_code == 200

    assert client.post("/api/analysis/website").status_code == 429
    assert client.post("/api/auth/login").status_code == 200


def test_unlimited_routes_are_not_limited(monkeypatch):
    monkeypatch.setattr(settings, "redis_url", None)
    monkeypatch.setattr(settings, "app_env", "development")
    client = make_client()

    for _ in range(15):
        assert client.get("/health").status_code == 200


def test_production_fails_closed_without_redis(monkeypatch):
    monkeypatch.setattr(settings, "redis_url", None)
    monkeypatch.setattr(settings, "app_env", "production")
    client = make_client()

    response = client.post("/api/auth/login")
    assert response.status_code == 503
