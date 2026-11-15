from fastapi.testclient import TestClient

from app.main import app
from app.api.routes import analysis


client = TestClient(app)


def test_website_api_requires_authorization():
    response = client.post(
        "/api/analysis/website",
        json={"url": "https://example.org", "authorized": False},
    )
    assert response.status_code == 403


def test_website_api_is_disabled_by_default(monkeypatch):
    monkeypatch.setattr(analysis.settings, "enable_website_scan", False)
    response = client.post(
        "/api/analysis/website",
        json={"url": "https://example.org", "authorized": True},
    )
    assert response.status_code == 503


def test_website_api_forwards_authorized_target(monkeypatch):
    async def fake_scan(url, *, authorized):
        assert url == "https://example.org"
        assert authorized is True
        return {"status": "completed", "findings": []}

    monkeypatch.setattr(analysis.settings, "enable_website_scan", True)
    monkeypatch.setattr(analysis, "scan_website_target", fake_scan)
    response = client.post(
        "/api/analysis/website",
        json={"url": "https://example.org", "authorized": True},
    )

    assert response.status_code == 200
    assert response.json()["analysis_type"] == "website_security_audit"
