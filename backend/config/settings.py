"""
Application Settings and Configuration
"""
from typing import List
from pydantic_settings import BaseSettings
from decouple import config


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = config("DATABASE_URL", default="postgresql://postgres:password@localhost:5432/user_management")

    # Security
    SECRET_KEY: str = config("SECRET_KEY", default="your-super-secret-key-change-this")
    ALGORITHM: str = config("ALGORITHM", default="HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = config("ACCESS_TOKEN_EXPIRE_MINUTES", default=30, cast=int)

    # Environment
    ENVIRONMENT: str = config("ENVIRONMENT", default="development")
    DEBUG: bool = config("DEBUG", default=True, cast=bool)

    # CORS
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8080", "http://127.0.0.1:8080"]

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = config("RATE_LIMIT_PER_MINUTE", default=60, cast=int)

    # Email Configuration
    EMAIL_HOST: str = config("EMAIL_HOST", default="smtp.gmail.com")
    EMAIL_PORT: int = config("EMAIL_PORT", default=587, cast=int)
    EMAIL_USE_TLS: bool = config("EMAIL_USE_TLS", default=True, cast=bool)
    EMAIL_USERNAME: str = config("EMAIL_USERNAME", default="")
    EMAIL_PASSWORD: str = config("EMAIL_PASSWORD", default="")
    EMAIL_FROM: str = config("EMAIL_FROM", default="")
    EMAIL_FROM_NAME: str = config("EMAIL_FROM_NAME", default="User Management System")
    EMAIL_FALLBACK_TO_FILE: bool = config("EMAIL_FALLBACK_TO_FILE", default=False, cast=bool)

    class Config:
        env_file = ".env"


settings = Settings()
