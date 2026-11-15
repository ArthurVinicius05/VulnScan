import json

from app.core.config import Settings


def test_cors_origins_loads_from_json_environment(monkeypatch):
    origins = ["http://localhost:5173", "https://app.example.test"]
    monkeypatch.setenv("CORS_ORIGINS", json.dumps(origins))
    settings = Settings(_env_file=None)
    assert settings.cors_origins == origins


def test_production_settings_require_a_separate_operations_secret():
    from cryptography.fernet import Fernet

    from app.core.production import validate_production_settings

    valid = Settings(
        _env_file=None,
        app_env="production",
        database_url="postgresql+psycopg://user:password@db:5432/vulnscan",
        redis_url="redis://redis:6379/0",
        cors_origins=["https://app.example.test"],
        frontend_url="https://app.example.test",
        session_cookie_secure=True,
        smtp_host="smtp-proxy",
        smtp_starttls=True,
        smtp_tls_server_name="smtp.example.test",
        smtp_upstream_host="smtp.example.test",
        mail_from="noreply@example.test",
        scanner_worker_token="s" * 40,
        ops_admin_token="o" * 40,
        mfa_encryption_key=Fernet.generate_key().decode(),
        monthly_analysis_limit=10,
        max_concurrent_analyses=2,
        max_queued_storage_mb=50,
        dead_letter_archive_retention_hours=72,
    )
    validate_production_settings(valid)

    invalid = Settings(
        _env_file=None,
        app_env="production",
        database_url=valid.database_url,
        redis_url=valid.redis_url,
        cors_origins=valid.cors_origins,
        frontend_url=valid.frontend_url,
        session_cookie_secure=True,
        smtp_host=valid.smtp_host,
        smtp_starttls=True,
        smtp_tls_server_name=valid.smtp_tls_server_name,
        smtp_upstream_host=valid.smtp_upstream_host,
        mail_from=valid.mail_from,
        scanner_worker_token=valid.scanner_worker_token,
        ops_admin_token=None,
        mfa_encryption_key=valid.mfa_encryption_key,
        monthly_analysis_limit=10,
        max_concurrent_analyses=2,
        max_queued_storage_mb=50,
        dead_letter_archive_retention_hours=72,
    )
    import pytest

    with pytest.raises(RuntimeError, match="OPS_ADMIN_TOKEN"):
        validate_production_settings(invalid)
