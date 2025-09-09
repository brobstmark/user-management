"""
Platform and User Platform Access Models - Simplified Version
"""
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, Integer, ForeignKey, Text, UniqueConstraint
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from backend.models.base import BaseModel


class Platform(BaseModel):
    """
    Registered platforms that can use the auth service
    Clean design with proper user ownership
    """
    __tablename__ = "platforms"

    # Primary Key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Ownership - Every platform belongs to a user
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)

    # Platform Identification
    name = Column(String(100), nullable=False)
    slug = Column(String(50), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)

    # Domain Configuration
    domain = Column(String(255), nullable=False, unique=True, index=True)
    return_url = Column(String(500), nullable=True)

    # API Security
    api_key_hash = Column(String(255), nullable=False, unique=True, index=True)
    api_key_prefix = Column(String(10), nullable=False)

    # Status
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    is_verified = Column(Boolean, default=False, nullable=False)

    # Audit Fields
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    last_used_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships - Simple and clean
    owner = relationship("User", back_populates="platforms")
    user_accesses = relationship("UserPlatformAccess", back_populates="platform", cascade="all, delete-orphan")

    # Table constraints
    __table_args__ = (
        UniqueConstraint('user_id', 'slug', name='uq_user_platform_slug'),
    )

    def __repr__(self):
        return f"<Platform(id={self.id}, slug={self.slug}, domain={self.domain}, owner_id={self.user_id})>"


class UserPlatformAccess(BaseModel):
    """
    Simple relationship: which users have access to which platforms
    NO AUDIT DATA - keeps relationships clean
    """
    __tablename__ = "user_platform_access"

    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # The core relationship - ONLY these two foreign keys
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    platform_id = Column(Integer, ForeignKey("platforms.id"), nullable=False, index=True)

    # Simple access control
    role = Column(String(20), default="user", nullable=False)  # "admin", "user", "readonly"
    is_active = Column(Boolean, default=True, nullable=False, index=True)

    # Basic timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Simple relationships - NO AMBIGUITY
    user = relationship("User", back_populates="platform_accesses")
    platform = relationship("Platform", back_populates="user_accesses")

    # Table constraints
    __table_args__ = (
        UniqueConstraint('user_id', 'platform_id', name='uq_user_platform_access'),
    )

    def __repr__(self):
        return f"<UserPlatformAccess(user_id={self.user_id}, platform_id={self.platform_id}, role={self.role})>"


class PlatformAccessAudit(BaseModel):
    """
    Separate audit table for tracking all access changes
    Who granted access, who revoked it, when, etc.
    """
    __tablename__ = "platform_access_audit"

    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # What happened
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    platform_id = Column(Integer, ForeignKey("platforms.id"), nullable=False, index=True)
    action = Column(String(50), nullable=False, index=True)  # 'granted', 'revoked', 'role_changed'

    # Who did it
    performed_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # State changes
    old_value = Column(String(100), nullable=True)  # Previous state
    new_value = Column(String(100), nullable=True)  # New state

    # When it happened
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

    # Relationships for audit queries
    user = relationship("User", foreign_keys=[user_id])
    platform = relationship("Platform", foreign_keys=[platform_id])
    performed_by = relationship("User", foreign_keys=[performed_by_user_id])

    def __repr__(self):
        return f"<PlatformAccessAudit(user_id={self.user_id}, platform_id={self.platform_id}, action={self.action})>"