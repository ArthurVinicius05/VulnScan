from fastapi.testclient import TestClient

from app.main import app
from app.core import auth


client = TestClient(app)


def test_analysis_routes_allow_local_development_without_key(monkeypatch):
    monkeypatch.setattr(auth.settings, "app_env", "development")
    monkeypatch.setattr(auth.settings, "api_key", None)

    response = client.post("/api/analysis/website", json={"url": "https://example.org", "authorized": False})

    assert response.status_code == 403


def test_analysis_routes_require_bearer_key_when_configured(monkeypatch):
    monkeypatch.setattr(auth.settings, "app_env", "development")
    monkeypatch.setattr(auth.settings, "api_key", "test-secret")

    response = client.post("/api/analysis/website", json={"url": "https://example.org", "authorized": True})

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_analysis_routes_accept_valid_bearer_key(monkeypatch):
    monkeypatch.setattr(auth.settings, "api_key", "test-secret")

    response = client.post(
        "/api/analysis/website",
        headers={"Authorization": "Bearer test-secret"},
        json={"url": "https://example.org", "authorized": False},
    )

    assert response.status_code == 403


def test_production_fails_closed_without_api_key(monkeypatch):
    monkeypatch.setattr(auth.settings, "app_env", "production")
    monkeypatch.setattr(auth.settings, "api_key", None)

    response = client.post("/api/analysis/website", json={"url": "https://example.org", "authorized": True})

    assert response.status_code == 503


def test_health_endpoint_remains_public():
    response = client.get("/api/health")

    assert response.status_code == 200
