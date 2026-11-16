from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from app.db.database import Base
from app.main import app


def test_metrics_endpoint_exposes_request_and_queue_metrics(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'metrics.db'}")
    Base.metadata.create_all(engine)
    monkeypatch.setattr("app.main.SessionLocal", sessionmaker(bind=engine))
    with TestClient(app) as client:
        response = client.get("/metrics")
    assert response.status_code == 200
    assert "vulnscan_http_requests_total" in response.text
    assert "vulnscan_analysis_jobs" in response.text
    engine.dispose()
