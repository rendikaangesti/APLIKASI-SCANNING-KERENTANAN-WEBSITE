from pydantic_settings import BaseSettings
from typing import Optional
import os

class Settings(BaseSettings):
    PROJECT_NAME: str = "DjoeraganCyber Web & API Security Suite"
    API_V1_STR: str = "/api/v1"
    VERSION: str = "2.0.0"
    
    # Database (Default to aiosqlite for zero-config local run, switchable to asyncpg PostgreSQL via env)
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "sqlite+aiosqlite:///./scanner.db"
    )
    
    # Redis / Celery
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    # Security & Scanning Parameters
    MAX_CRAWL_DEPTH: int = 2
    MAX_CRAWL_PAGES: int = 30
    HTTP_TIMEOUT_SECONDS: float = 8.0
    USER_AGENT: str = "DjoeraganCyber-Security-Audit/2026.1 (+https://djoeragancyber.com)"
    
    # JWT / Auth
    SECRET_KEY: str = os.getenv("SECRET_KEY", "super-secret-key-change-in-production-123456789")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24

    class Config:
        case_sensitive = True
        env_file = ".env"

settings = Settings()
