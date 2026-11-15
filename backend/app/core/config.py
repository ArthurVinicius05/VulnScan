from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_env: str = "development"
    api_key: str | None = None
    database_url: str = "sqlite:///./vulnscan.db"
    cors_origins: list[str] = ["http://localhost:5173"]
    session_cookie_secure: bool = False
    max_upload_mb: int = 25
    max_archive_files: int = 3000
    max_extracted_mb: int = 100
    scanner_worker_url: str = "http://scanner-worker:8001"
    scanner_worker_timeout_seconds: float = 30.0
    enable_osv_scan: bool = False
    osv_worker_url: str = "http://osv-worker:8002"
    osv_worker_timeout_seconds: float = 55.0
    enable_website_scan: bool = False
    website_worker_url: str = "http://website-worker:8003"
    website_worker_timeout_seconds: float = 20.0

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
