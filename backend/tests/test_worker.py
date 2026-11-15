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
