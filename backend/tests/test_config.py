import json

from app.core.config import Settings


def test_cors_origins_loads_from_json_environment(monkeypatch):
    origins = ["http://localhost:5173", "https://app.example.test"]
    monkeypatch.setenv("CORS_ORIGINS", json.dumps(origins))
    settings = Settings(_env_file=None)
    assert settings.cors_origins == origins
