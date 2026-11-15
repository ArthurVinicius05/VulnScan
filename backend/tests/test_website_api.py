import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api.routes import analysis
from app.api.routes.auth import get_current_user
from app.models.user import User


@pytest.fixture(autouse=True)
def authenticated_user():
    app.dependency_overrides[get_current_user] = lambda: User(id="test-user", email="test@example.com", password_hash="unused")
    yield
    app.dependency_overrides.clear()


client = TestClient(app)


def test_website_api_requires_authorization():
    response = client.post("/api/analysis/website", json={"url": "https://example.org", "authorized": False})
    assert response.status_code == 403


def test_website_api_is_disabled_by_default(monkeypatch):
    monkeypatch.setattr(analysis.settings, "enable_website_scan", False)
    response = client.post("/api/analysis/website", json={"url": "https://example.org", "authorized": True})
    assert response.status_code == 503


def test_website_api_forwards_authorized_target(monkeypatch):
    async def fake_scan(url, *, authorized):
        assert url == "https://example.org"
        assert authorized is True
        return {"status": "completed", "findings": []}

    monkeypatch.setattr(analysis.settings, "enable_website_scan", True)
    monkeypatch.setattr(analysis, "scan_website_target", fake_scan)
    monkeypatch.setattr(analysis, "save_audit", lambda **kwargs: None)
    response = client.post("/api/analysis/website", json={"url": "https://example.org", "authorized": True})
    assert response.status_code == 200
    assert response.json()["analysis_type"] == "website_security_audit"
