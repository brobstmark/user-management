"""
CRUD operations for Platform and UserPlatformAccess models
"""
from datetime import datetime
from sqlalchemy.orm import Session
from backend.models.platforms import Platform, UserPlatformAccess


def create_platform(db: Session, name: str, domain: str, api_key_hash: str,
                   description: str = None, return_url: str = None) -> Platform:
    """Create a new platform"""
    platform = Platform(
        name=name,
        description=description,
        domain=domain,
        return_url=return_url,
        api_key=api_key_hash,
        is_active=True,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )

    db.add(platform)
    db.commit()
    db.refresh(platform)
    return platform


def get_platform(db: Session, platform_id: str) -> Platform:
    """Get platform by ID"""
    return db.query(Platform).filter(Platform.id == platform_id).first()


def get_platform_by_domain(db: Session, domain: str) -> Platform:
    """Get platform by domain"""
    return db.query(Platform).filter(Platform.domain == domain).first()


def get_platform_by_api_key_hash(db: Session, api_key_hash: str) -> Platform:
    """Get platform by API key hash"""
    return db.query(Platform).filter(Platform.api_key == api_key_hash).first()


def list_platforms(db: Session) -> list[Platform]:
    """List all platforms"""
    return db.query(Platform).order_by(Platform.created_at.desc()).all()


def update_platform(db: Session, platform_id: str, **kwargs) -> Platform:
    """Update platform details"""
    platform = get_platform(db, platform_id)
    if not platform:
        return None

    for key, value in kwargs.items():
        if hasattr(platform, key):
            setattr(platform, key, value)

    platform.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(platform)
    return platform


def deactivate_platform(db: Session, platform_id: str) -> bool:
    """Deactivate a platform"""
    platform = get_platform(db, platform_id)
    if not platform:
        return False

    platform.is_active = False
    platform.updated_at = datetime.utcnow()
    db.commit()
    return True


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


def get_platform_users(db: Session, platform_id: str) -> list:
    """Get all users who have access to a platform"""
    accesses = db.query(UserPlatformAccess).filter(
        UserPlatformAccess.platform_id == platform_id,
        UserPlatformAccess.is_active == True
    ).all()

    return [access.user_id for access in accesses]