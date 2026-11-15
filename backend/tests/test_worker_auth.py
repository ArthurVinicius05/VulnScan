import pytest
from fastapi import HTTPException

from app.core.config import settings
from app.worker import verify_worker_authorization


def test_worker_requires_shared_token_in_production(monkeypatch):
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "scanner_worker_token", "test-secret")

    with pytest.raises(HTTPException) as error:
        verify_worker_authorization(None)

    assert error.value.status_code == 401
    verify_worker_authorization("Bearer test-secret")


def test_worker_fails_closed_when_production_token_is_missing(monkeypatch):
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "scanner_worker_token", None)

    with pytest.raises(HTTPException) as error:
        verify_worker_authorization(None)

    assert error.value.status_code == 503


def test_worker_allows_local_development_without_shared_token(monkeypatch):
    monkeypatch.setattr(settings, "app_env", "development")
    monkeypatch.setattr(settings, "scanner_worker_token", None)
    verify_worker_authorization(None)
