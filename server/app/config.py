from functools import lru_cache

from pydantic import Field, HttpUrl, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SCADAGUARD_", env_file=".env", extra="ignore")

    database_url: SecretStr = SecretStr(
        "postgresql+asyncpg://scadaguard:scadaguard@localhost:5432/scadaguard"
    )
    secret_key: SecretStr = Field(min_length=32)
    public_url: HttpUrl = HttpUrl("http://localhost:8080")
    mattermost_webhook_url: SecretStr | None = None
    cookie_secure: bool = True
    log_level: str = "INFO"
    default_offline_threshold_seconds: int = Field(default=90, ge=30)
    signal_retention_days: int = Field(default=30, ge=1)
    check_retention_days: int = Field(default=90, ge=1)


@lru_cache
def get_settings() -> Settings:
    # Required secrets are supplied by the process environment at runtime.
    return Settings()  # type: ignore[call-arg]
