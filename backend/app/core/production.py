from __future__ import annotations

from urllib.parse import unquote, urlparse

from app.core.config import Settings, settings


def validate_production_settings(config: Settings = settings) -> None:
    """Fail startup when a production deployment is missing critical safeguards."""
    if config.app_env.strip().lower() != "production":
        return

    errors: list[str] = []

    if not config.database_url.startswith("postgresql+psycopg://"):
        errors.append("DATABASE_URL must use PostgreSQL with the psycopg driver")
    else:
        database_password = unquote(urlparse(config.database_url).password or "")
        if len(database_password) < 32 or any(
            marker in database_password.lower()
            for marker in ("change_me", "replace_with", "url_encoded_password")
        ):
            errors.append("DATABASE_URL must contain a unique password with at least 32 characters")
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
    if not config.ops_admin_token or len(config.ops_admin_token) < 32:
        errors.append("OPS_ADMIN_TOKEN must contain at least 32 characters")
    if not 1 <= config.dead_letter_archive_retention_hours <= 720:
        errors.append("DEAD_LETTER_ARCHIVE_RETENTION_HOURS must be between 1 and 720")
    if not config.smtp_host or not config.mail_from:
        errors.append("SMTP_HOST and MAIL_FROM are required for account verification and recovery")
    if bool(config.smtp_username) != bool(config.smtp_password):
        errors.append("SMTP_USERNAME and SMTP_PASSWORD must either both be set or both be empty")
    if config.smtp_host == "smtp-proxy":
        if not config.smtp_upstream_host:
            errors.append("SMTP_UPSTREAM_HOST must be configured when using the SMTP proxy")
        if not config.smtp_tls_server_name:
            errors.append("SMTP_TLS_SERVER_NAME must match the configured upstream SMTP certificate hostname")
        elif config.smtp_upstream_host and config.smtp_tls_server_name.lower() != config.smtp_upstream_host.lower():
            errors.append("SMTP_TLS_SERVER_NAME must exactly match SMTP_UPSTREAM_HOST")
    if not config.smtp_starttls:
        errors.append("SMTP_STARTTLS must be enabled")
    if config.enable_website_scan or config.enable_osv_scan:
        errors.append("Website and OSV scanning must remain disabled until egress controls are validated")
    if not config.mfa_encryption_key:
        errors.append("MFA_ENCRYPTION_KEY is required to encrypt MFA secrets at rest")
    else:
        try:
            from cryptography.fernet import Fernet
            Fernet(config.mfa_encryption_key.encode("ascii"))
        except (ValueError, UnicodeEncodeError):
            errors.append("MFA_ENCRYPTION_KEY must be a valid Fernet key")
    if config.monthly_analysis_limit < 1:
        errors.append("MONTHLY_ANALYSIS_LIMIT must be at least 1")
    if not 1 <= config.max_concurrent_analyses <= config.monthly_analysis_limit:
        errors.append("MAX_CONCURRENT_ANALYSES must be between 1 and MONTHLY_ANALYSIS_LIMIT")
    if config.max_queued_storage_mb < config.max_upload_mb:
        errors.append("MAX_QUEUED_STORAGE_MB must be at least MAX_UPLOAD_MB")
    if not 1 <= config.analysis_job_retention_days <= 3650:
        errors.append("ANALYSIS_JOB_RETENTION_DAYS must be between 1 and 3650")
    if not 1 <= config.audit_retention_days <= 3650:
        errors.append("AUDIT_RETENTION_DAYS must be between 1 and 3650")
    if not 1 <= config.max_upload_mb <= 100:
        errors.append("MAX_UPLOAD_MB must be between 1 and 100")
    if not 1 <= config.max_archive_files <= 10000:
        errors.append("MAX_ARCHIVE_FILES must be between 1 and 10000")
    if not 1 <= config.max_extracted_mb <= 500:
        errors.append("MAX_EXTRACTED_MB must be between 1 and 500")

    if errors:
        details = "; ".join(errors)
        raise RuntimeError(f"Unsafe production configuration: {details}.")
