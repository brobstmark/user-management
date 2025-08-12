"""
Health Check Endpoints
"""
from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def health_check():
    return {"status": "healthy", "service": "user-management-system"}

@router.get("/db")
async def database_health():
    # TODO: Add actual database health check
    return {"status": "healthy", "database": "connected"}
