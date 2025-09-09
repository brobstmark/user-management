"""
Models package initialization
Import all models to ensure they are registered with SQLAlchemy
"""
from backend.config.database import Base
from backend.models.base import BaseModel
from backend.models.user import User
from backend.models.platforms import Platform, UserPlatformAccess

# Export models for easy importing
__all__ = ["Base", "BaseModel", "User", "Platform", "UserPlatformAccess"]