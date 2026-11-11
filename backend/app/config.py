"""Settings. Every secret comes from the environment (.env via docker compose)."""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    admin_username: str = "admin"
    # Required by the API (checked in validate_api_settings); the worker does not receive them.
    admin_password: str = ""
    jwt_secret: str = ""
    jwt_expire_minutes: int = 480
    token_encryption_key: str = ""

    postgres_user: str = "vapt"
    postgres_password: str = ""
    postgres_db: str = "vapt"
    postgres_host: str = "db"
    database_url: str = ""

    data_dir: str = "/data"
    max_upload_mb: int = 100
    max_extract_mb: int = 500
    max_extract_files: int = 20000
    max_repo_mb: int = 1000
    scan_timeout_seconds: int = 1800

    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-5-5"

    def validate_api_settings(self) -> None:
        problems = []
        if len(self.admin_password) < 12 or self.admin_password.startswith("change-me"):
            problems.append("ADMIN_PASSWORD must be set and at least 12 characters")
        if len(self.jwt_secret) < 32 or self.jwt_secret.startswith("replace-with"):
            problems.append("JWT_SECRET must be set and at least 32 characters")
        if problems:
            raise RuntimeError("Invalid .env: " + "; ".join(problems))

    @property
    def sqlalchemy_url(self) -> str:
        if self.database_url:
            return self.database_url
        return (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:5432/{self.postgres_db}"
        )

    @property
    def ai_enabled(self) -> bool:
        return bool(self.anthropic_api_key.strip())


@lru_cache
def get_settings() -> Settings:
    return Settings()
