"""
Configuration Endpoints
"""
from fastapi import APIRouter
from backend.config.settings import settings

router = APIRouter()


@router.get("/config")
async def get_frontend_config():
    """
    Get frontend configuration

    Returns environment-specific settings for the frontend application.
    This endpoint provides:
    - API URLs and timeouts
    - Feature flags
    - Security settings
    - UI preferences
    - Environment information
    """
    return settings.get_frontend_config()


@router.get("/config/health")
async def config_health():
    """
    Config service health check
    """
    return {
        "status": "healthy",
        "environment": settings.ENVIRONMENT,
        "debug": settings.DEBUG,
        "version": "1.0.0"
    }