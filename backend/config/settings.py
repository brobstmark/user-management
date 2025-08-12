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

    # Domain Configuration (for CORS and frontend)
    FRONTEND_URL: str = config("FRONTEND_URL", default="http://localhost:8000")
    API_URL: str = config("API_URL", default="http://localhost:8000")
    DOMAIN: str = config("DOMAIN", default="localhost:8000")

    # CORS - Dynamic based on environment
    ALLOWED_ORIGINS: List[str] = []

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

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._setup_environment_config()

    def _setup_environment_config(self):
        """Setup environment-specific configuration"""
        if self.ENVIRONMENT == "development":
            self.ALLOWED_ORIGINS = [
                "http://localhost:3000",
                "http://localhost:8000",
                "http://localhost:8080",
                "http://127.0.0.1:3000",
                "http://127.0.0.1:8000",
                "http://127.0.0.1:8080"
            ]
        elif self.ENVIRONMENT == "staging":
            # Add staging-specific origins
            self.ALLOWED_ORIGINS = [
                self.FRONTEND_URL,
                f"https://{self.DOMAIN}",
                f"http://{self.DOMAIN}",
                # Add staging subdomains
                f"https://staging.{self.DOMAIN.split(':')[0] if ':' in self.DOMAIN else self.DOMAIN}",
                f"https://staging-api.{self.DOMAIN.split(':')[0] if ':' in self.DOMAIN else self.DOMAIN}"
            ]
        elif self.ENVIRONMENT == "production":
            # Production - be more strict with origins
            base_domain = self.DOMAIN.split(':')[0] if ':' in self.DOMAIN else self.DOMAIN
            self.ALLOWED_ORIGINS = [
                self.FRONTEND_URL,
                f"https://{self.DOMAIN}",
                f"https://www.{base_domain}",
                f"https://app.{base_domain}",
                f"https://api.{base_domain}"
            ]
        else:
            # Custom environment - use provided URLs
            self.ALLOWED_ORIGINS = [self.FRONTEND_URL, self.API_URL]

    def get_frontend_config(self) -> dict:
        """Get configuration for frontend consumption"""
        # Use relative URLs when frontend is served from same domain as API
        if self.FRONTEND_URL == self.API_URL:
            api_base_url = "/api/v1"
        else:
            api_base_url = f"{self.API_URL}/api/v1"

        return {
            "api": {
                "baseUrl": api_base_url,
                "timeout": 30000,
                "retries": 3
            },
            "app": {
                "name": "User Management System",
                "version": "1.0.0",
                "environment": self.ENVIRONMENT,
                "debug": self.DEBUG
            },
            "features": {
                "emailVerification": True,
                "passwordReset": True,
                "usernameRecovery": True,
                "twoFactorAuth": False,  # Future feature
                "socialAuth": False  # Future feature
            },
            "security": {
                "tokenExpiry": self.ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # in seconds
                "maxLoginAttempts": 5,
                "passwordMinLength": 8
            },
            "ui": {
                "theme": "light",
                "showDebugInfo": self.DEBUG,
                "enableAnalytics": self.ENVIRONMENT == "production"
            }
        }

    class Config:
        env_file = ".env"


settings = Settings()