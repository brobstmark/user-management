"""
Platform and User Platform Access Models
"""
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, Integer, ForeignKey
from sqlalchemy.orm import relationship

from backend.models.base import BaseModel


class Platform(BaseModel):
    """
    Registered platforms that can use the auth service
    """
    __tablename__ = "platforms"

    id = Column(String(50), primary_key=True)  # "space-game", "rpg-world"
    name = Column(String(100), nullable=False)  # "Space Adventure Game"
    domain = Column(String(255), nullable=False)  # "spacegame.com"
    is_active = Column(Boolean, default=True, nullable=False)

    # Relationship to user access
    user_accesses = relationship("UserPlatformAccess", back_populates="platform")

    def __repr__(self):
        return f"<Platform(id={self.id}, name={self.name}, active={self.is_active})>"


class UserPlatformAccess(BaseModel):
    """
    Tracks which users have access to which platforms
    """
    __tablename__ = "user_platform_access"

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    platform_id = Column(String(50), ForeignKey("platforms.id"), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    # Relationships
    user = relationship("User", back_populates="platform_accesses")
    platform = relationship("Platform", back_populates="user_accesses")

    def __repr__(self):
        return f"<UserPlatformAccess(user_id={self.user_id}, platform_id={self.platform_id})>"