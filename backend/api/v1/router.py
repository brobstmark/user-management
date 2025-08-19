"""
Main API Router for v1
"""
from fastapi import APIRouter

from backend.api.v1 import auth, users, health, frontend_logs

api_router = APIRouter()

api_router.include_router(health.router, prefix="/health", tags=["health"])
api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
api_router.include_router(frontend_logs.router, prefix="/logs", tags=["logs"])
