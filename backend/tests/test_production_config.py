import pytest

from app.core.config import Settings
from app.core.production import validate_production_settings


def production_settings(**overrides):
    values = {
        "app_env": "production",
        "database_url": "postgresql+psycopg://vulnscan:secret@db:5432/vulnscan",
        "redis_url": "redis://redis:6379/0",
        "cors_origins": ["https://vulnscan.example.test"],
        "frontend_url": "https://vulnscan.example.test",
        "session_cookie_secure": True,
        "scanner_worker_token": "a" * 48,
        "mfa_encryption_key": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=",
        "smtp_host": "smtp.example.test",
        "smtp_port": 587,
        "smtp_starttls": True,
        "mail_from": "noreply@example.test",
        "enable_website_scan": False,
        "enable_osv_scan": False,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def test_valid_production_configuration_is_accepted():
    validate_production_settings(production_settings())


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"database_url": "sqlite:///./vulnscan.db"}, "PostgreSQL"),
        ({"redis_url": None}, "REDIS_URL"),
        ({"cors_origins": ["http://insecure.example.test"]}, "HTTPS origins"),
        ({"frontend_url": "http://vulnscan.example.test"}, "FRONTEND_URL"),
        ({"session_cookie_secure": False}, "SESSION_COOKIE_SECURE"),
        ({"scanner_worker_token": "short"}, "SCANNER_WORKER_TOKEN"),
        ({"mfa_encryption_key": None}, "MFA_ENCRYPTION_KEY"),
        ({"smtp_host": None}, "SMTP_HOST"),
        ({"smtp_host": "smtp-proxy"}, "SMTP_TLS_SERVER_NAME"),
        ({"smtp_username": "user"}, "SMTP_USERNAME"),
        ({"smtp_starttls": False}, "SMTP_STARTTLS"),
        ({"enable_website_scan": True}, "egress controls"),
        ({"max_upload_mb": 1000}, "MAX_UPLOAD_MB"),
        ({"monthly_analysis_limit": 0}, "MONTHLY_ANALYSIS_LIMIT"),
        ({"max_concurrent_analyses": 0}, "MAX_CONCURRENT_ANALYSES"),
    ],
)
def test_unsafe_production_configuration_fails_closed(override, message):
    with pytest.raises(RuntimeError, match=message):
        validate_production_settings(production_settings(**override))


def test_development_configuration_is_not_subject_to_production_requirements():
    validate_production_settings(Settings(_env_file=None, app_env="development"))
