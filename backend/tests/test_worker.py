from fastapi.testclient import TestClient

from app.worker import app


def test_worker_health():
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json()["service"] == "scanner-worker"


def test_worker_rejects_oversized_archive(monkeypatch):
    import app.worker as worker

    monkeypatch.setattr(worker, "MAX_UPLOAD_BYTES", 8)
    response = TestClient(app).post(
        "/scan/python",
        files={"file": ("source.zip", b"x" * 9, "application/zip")},
    )
    assert response.status_code == 413


def test_worker_returns_scanner_result_for_archive(monkeypatch):
    import app.worker as worker

    expected = {"status": "skipped", "tools": [], "findings": []}
    monkeypatch.setattr(worker, "run_python_tools", lambda content: expected)
    response = TestClient(app).post(
        "/scan/python",
        files={"file": ("source.zip", b"small archive", "application/zip")},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == expected["status"]
    assert payload["tools"] == expected["tools"]
    assert payload["findings"] == expected["findings"]
    assert [tool["name"] for tool in payload["security_tools"]] == ["Gitleaks", "OSV-Scanner"]
    assert payload["security_tools"][1]["status"] == "disabled"
