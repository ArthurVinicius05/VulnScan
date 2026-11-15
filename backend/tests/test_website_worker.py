from fastapi.testclient import TestClient

from app.services import website_worker
from app.services.target_validation import TargetValidationError


client = TestClient(website_worker.app)


def test_worker_requires_explicit_authorization():
    response = client.post("/scan", json={"url": "https://example.org", "authorized": False})
    assert response.status_code == 403


def test_worker_rejects_missing_authorization_field():
    response = client.post("/scan", json={"url": "https://example.org"})
    assert response.status_code == 422


def test_worker_calls_passive_scanner_after_authorization(monkeypatch):
    expected = {"status": "completed", "scan_type": "passive_http_headers", "findings": []}
    seen = []

    def fake_scan(url):
        seen.append(url)
        return expected

    monkeypatch.setattr(website_worker, "scan_website", fake_scan)
    response = client.post("/scan", json={"url": "https://example.org", "authorized": True})

    assert response.status_code == 200
    assert response.json() == expected
    assert seen == ["https://example.org"]


def test_worker_returns_validation_error_without_connecting(monkeypatch):
    def reject(_url):
        raise TargetValidationError("IP não público")

    monkeypatch.setattr(website_worker, "scan_website", reject)
    response = client.post("/scan", json={"url": "http://127.0.0.1", "authorized": True})

    assert response.status_code == 400
    assert "não público" in response.json()["detail"]
