"""
app/core/config.py
All settings loaded from environment variables / .env file.
"""

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ── App ───────────────────────────────────────────────────────────────────
    APP_NAME:        str  = "Multi-Cloud Pentest Platform"
    APP_VERSION:     str  = "1.0.0"
    ENVIRONMENT:     str  = "development"
    DEBUG:           bool = True

    # ── API ───────────────────────────────────────────────────────────────────
    API_HOST:        str  = "0.0.0.0"
    API_PORT:        int  = 8000
    API_WORKERS:     int  = 1
    CORS_ORIGINS:    str  = "http://localhost:3000,http://localhost:8000,http://127.0.0.1:3000,http://127.0.0.1:8000,http://localhost:5500,http://127.0.0.1:5500,null"

    # ── Database ──────────────────────────────────────────────────────────────
    DATABASE_URL:    str  = "sqlite+aiosqlite:///./mcpp.db"   # swap to postgres in prod

    # ── Redis ─────────────────────────────────────────────────────────────────
    REDIS_URL:       str  = "redis://localhost:6379/0"
    CELERY_BROKER:   str  = "redis://localhost:6379/1"
    CELERY_BACKEND:  str  = "redis://localhost:6379/2"

    # ── JWT ───────────────────────────────────────────────────────────────────
    JWT_SECRET_KEY:  str  = "dev-secret-CHANGE-IN-PRODUCTION"
    JWT_ALGORITHM:   str  = "HS256"
    JWT_EXPIRE_MIN:  int  = 60

    # ── Security ──────────────────────────────────────────────────────────────
    BCRYPT_ROUNDS:   int  = 12

    # ── Scanning ──────────────────────────────────────────────────────────────
    MAX_CONCURRENT_SCANS: int = 5
    SCAN_TIMEOUT_MIN:     int = 120
    DEFAULT_REGIONS:      str = "us-east-1,eu-west-1"

    # ── Reports ───────────────────────────────────────────────────────────────
    REPORTS_DIR:     str  = "./reports"

    # ── Logging ───────────────────────────────────────────────────────────────
    LOG_LEVEL:       str  = "INFO"

    # ── AI ────────────────────────────────────────────────────────────────────
    ANTHROPIC_API_KEY: str = ""

    # ── Properties ───────────────────────────────────────────────────────────
    @property
    def cors_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",")]

    @property
    def default_regions_list(self) -> list[str]:
        return [r.strip() for r in self.DEFAULT_REGIONS.split(",")]

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
