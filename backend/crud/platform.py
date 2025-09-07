"""
CRUD operations for Platform and UserPlatformAccess models
"""
from sqlalchemy.orm import Session
from backend.models.platforms import Platform, UserPlatformAccess


def get_platform(db: Session, platform_id: str) -> Platform:
    """Get platform by ID"""
    return db.query(Platform).filter(Platform.id == platform_id).first()


def has_platform_access(db: Session, user_id: int, platform_id: str) -> bool:
    """Check if user has access to platform"""
    access = db.query(UserPlatformAccess).filter(
        UserPlatformAccess.user_id == user_id,
        UserPlatformAccess.platform_id == platform_id,
        UserPlatformAccess.is_active == True
    ).first()
    return access is not None


def grant_platform_access(db: Session, user_id: int, platform_id: str) -> bool:
    """Grant user access to platform"""
    # Check if access already exists
    if has_platform_access(db, user_id, platform_id):
        return True

    # Create new access record
    access = UserPlatformAccess(
        user_id=user_id,
        platform_id=platform_id,
        is_active=True
    )
    db.add(access)
    db.commit()
    return True


def revoke_platform_access(db: Session, user_id: int, platform_id: str) -> bool:
    """Revoke user access to platform"""
    access = db.query(UserPlatformAccess).filter(
        UserPlatformAccess.user_id == user_id,
        UserPlatformAccess.platform_id == platform_id
    ).first()

    if access:
        access.is_active = False
        db.commit()
        return True

    return False  # Access record not found


def get_user_platforms(db: Session, user_id: int) -> list:
    """Get all platforms user has access to"""
    accesses = db.query(UserPlatformAccess).filter(
        UserPlatformAccess.user_id == user_id,
        UserPlatformAccess.is_active == True
    ).all()

    return [access.platform_id for access in accesses]