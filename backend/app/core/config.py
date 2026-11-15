from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_env: str = "development"
    cors_origins: list[str] = ["http://localhost:5173"]
    max_upload_mb: int = 25
    max_archive_files: int = 3000
    max_extracted_mb: int = 100
    scanner_worker_url: str = "http://scanner-worker:8001"
    scanner_worker_timeout_seconds: float = 30.0

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
