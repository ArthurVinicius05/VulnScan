from __future__ import annotations

from urllib.parse import urlparse

from app.core.config import Settings, settings


def validate_production_settings(config: Settings = settings) -> None:
    """Fail startup when a production deployment is missing critical safeguards."""
    if config.app_env.strip().lower() != "production":
        return

    errors: list[str] = []

    if not config.database_url.startswith("postgresql+psycopg://"):
        errors.append("DATABASE_URL must use PostgreSQL with the psycopg driver")
    if not config.redis_url or not config.redis_url.startswith(("redis://", "rediss://")):
        errors.append("REDIS_URL must point to a dedicated Redis service")
    if not config.cors_origins or any(
        urlparse(origin).scheme != "https" or not urlparse(origin).netloc
        for origin in config.cors_origins
    ):
        errors.append("CORS_ORIGINS must contain only explicit HTTPS origins")
    frontend = urlparse(config.frontend_url)
    if frontend.scheme != "https" or not frontend.netloc:
        errors.append("FRONTEND_URL must be an HTTPS URL")
    if not config.session_cookie_secure:
        errors.append("SESSION_COOKIE_SECURE must be enabled")
    if not config.scanner_worker_token or len(config.scanner_worker_token) < 32:
        errors.append("SCANNER_WORKER_TOKEN must contain at least 32 characters")
    if not config.smtp_host or not config.mail_from:
        errors.append("SMTP_HOST and MAIL_FROM are required for account verification and recovery")
    if bool(config.smtp_username) != bool(config.smtp_password):
        errors.append("SMTP_USERNAME and SMTP_PASSWORD must either both be set or both be empty")
    if not config.smtp_starttls:
        errors.append("SMTP_STARTTLS must be enabled")
    if config.enable_website_scan or config.enable_osv_scan:
        errors.append("Website and OSV scanning must remain disabled until egress controls are validated")
    if not 1 <= config.max_upload_mb <= 100:
        errors.append("MAX_UPLOAD_MB must be between 1 and 100")
    if not 1 <= config.max_archive_files <= 10000:
        errors.append("MAX_ARCHIVE_FILES must be between 1 and 10000")
    if not 1 <= config.max_extracted_mb <= 500:
        errors.append("MAX_EXTRACTED_MB must be between 1 and 500")

    if errors:
        details = "; ".join(errors)
        raise RuntimeError(f"Unsafe production configuration: {details}.")
