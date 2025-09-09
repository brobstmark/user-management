"""
CRUD operations for Platform and UserPlatformAccess models
Updated for industry-standard platform management
"""
import secrets
import hashlib
import re
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import and_
from backend.models.platforms import Platform, UserPlatformAccess


def generate_api_key() -> str:
    """Generate a secure API key with standard prefix"""
    random_part = secrets.token_urlsafe(32)
    return f"pk_{random_part}"


def hash_api_key(api_key: str) -> str:
    """Hash API key for secure storage"""
    return hashlib.sha256(api_key.encode()).hexdigest()


def generate_slug(name: str, user_id: int, db: Session) -> str:
    """Generate unique slug from platform name"""
    # Create base slug from name
    base_slug = re.sub(r'[^a-zA-Z0-9]+', '-', name.lower()).strip('-')
    base_slug = base_slug[:45]  # Leave room for counter

    if not base_slug:
        base_slug = 'platform'

    # Check if slug already exists for this user
    existing = db.query(Platform).filter(
        and_(Platform.user_id == user_id, Platform.slug == base_slug)
    ).first()

    if not existing:
        return base_slug

    # Find available slug with counter
    counter = 1
    while True:
        candidate_slug = f"{base_slug}-{counter}"
        existing = db.query(Platform).filter(
            and_(Platform.user_id == user_id, Platform.slug == candidate_slug)
        ).first()

        if not existing:
            return candidate_slug

        counter += 1
        if counter > 999:  # Safety limit
            raise ValueError("Cannot generate unique slug")


def create_platform(db: Session, user_id: int, name: str, domain: str,
                    description: str = None, return_url: str = None) -> dict:
    """
    Create a new platform for a user

    Returns:
        dict with 'success', 'platform', 'api_key' (raw), and 'errors'
    """
    try:
        # Validation
        errors = []

        if not name or len(name.strip()) < 1:
            errors.append("Platform name is required")
        elif len(name.strip()) > 100:
            errors.append("Platform name too long (max 100 characters)")

        if not domain or len(domain.strip()) < 3:
            errors.append("Domain is required")
        elif len(domain.strip()) > 255:
            errors.append("Domain too long (max 255 characters)")

        # Check if domain already exists
        if domain:
            existing_domain = db.query(Platform).filter(Platform.domain == domain.strip().lower()).first()
            if existing_domain:
                errors.append("This domain is already registered to another platform")

        if errors:
            return {
                "success": False,
                "errors": errors,
                "platform": None,
                "api_key": None
            }

        # Generate unique slug
        slug = generate_slug(name.strip(), user_id, db)

        # Generate API key and hash it
        api_key = generate_api_key()
        api_key_hash = hash_api_key(api_key)
        api_key_prefix = api_key[:7] + "..."  # "pk_abc123..."

        # Create platform
        platform = Platform(
            user_id=user_id,
            name=name.strip(),
            slug=slug,
            description=description.strip() if description else None,
            domain=domain.strip().lower(),
            return_url=return_url.strip() if return_url else None,
            api_key_hash=api_key_hash,
            api_key_prefix=api_key_prefix,
            is_active=True,
            is_verified=False  # Requires domain verification
        )

        db.add(platform)
        db.commit()
        db.refresh(platform)

        return {
            "success": True,
            "platform": platform,
            "api_key": api_key,  # Return raw key (only time it's available)
            "errors": []
        }

    except Exception as e:
        db.rollback()
        return {
            "success": False,
            "errors": [f"Failed to create platform: {str(e)}"],
            "platform": None,
            "api_key": None
        }


def get_platform(db: Session, platform_id: int) -> Platform:
    """Get platform by ID"""
    return db.query(Platform).filter(Platform.id == platform_id).first()


def get_platform_by_slug(db: Session, user_id: int, slug: str) -> Platform:
    """Get platform by user ID and slug"""
    return db.query(Platform).filter(
        and_(Platform.user_id == user_id, Platform.slug == slug)
    ).first()


def get_platform_by_domain(db: Session, domain: str) -> Platform:
    """Get platform by domain"""
    return db.query(Platform).filter(Platform.domain == domain.lower()).first()


def get_platform_by_api_key_hash(db: Session, api_key_hash: str) -> Platform:
    """Get platform by API key hash"""
    return db.query(Platform).filter(Platform.api_key_hash == api_key_hash).first()


def get_user_platforms(db: Session, user_id: int) -> list[Platform]:
    """Get all platforms owned by a user"""
    return db.query(Platform).filter(
        and_(Platform.user_id == user_id, Platform.is_active == True)
    ).order_by(Platform.created_at.desc()).all()


def update_platform(db: Session, platform_id: int, user_id: int, **kwargs) -> dict:
    """Update platform details (only by owner)"""
    platform = db.query(Platform).filter(
        and_(Platform.id == platform_id, Platform.user_id == user_id)
    ).first()

    if not platform:
        return {"success": False, "error": "Platform not found or access denied"}

    # Update allowed fields
    allowed_fields = ['name', 'description', 'return_url']
    for key, value in kwargs.items():
        if key in allowed_fields and hasattr(platform, key):
            setattr(platform, key, value)

    # Regenerate slug if name changed
    if 'name' in kwargs:
        platform.slug = generate_slug(kwargs['name'], user_id, db)

    try:
        db.commit()
        db.refresh(platform)
        return {"success": True, "platform": platform}
    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}


def deactivate_platform(db: Session, platform_id: int, user_id: int) -> bool:
    """Deactivate a platform (only by owner)"""
    platform = db.query(Platform).filter(
        and_(Platform.id == platform_id, Platform.user_id == user_id)
    ).first()

    if not platform:
        return False

    platform.is_active = False
    db.commit()
    return True


def regenerate_api_key(db: Session, platform_id: int, user_id: int) -> dict:
    """Regenerate API key for a platform (only by owner)"""
    platform = db.query(Platform).filter(
        and_(Platform.id == platform_id, Platform.user_id == user_id)
    ).first()

    if not platform:
        return {"success": False, "error": "Platform not found or access denied"}

    # Generate new API key
    new_api_key = generate_api_key()
    new_api_key_hash = hash_api_key(new_api_key)
    new_api_key_prefix = new_api_key[:10] + "..."

    platform.api_key_hash = new_api_key_hash
    platform.api_key_prefix = new_api_key_prefix

    try:
        db.commit()
        return {
            "success": True,
            "api_key": new_api_key,  # Return raw key (only time it's available)
            "platform": platform
        }
    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}


# UserPlatformAccess CRUD functions

def has_platform_access(db: Session, user_id: int, platform_id: int) -> bool:
    """Check if user has access to platform"""
    access = db.query(UserPlatformAccess).filter(
        and_(
            UserPlatformAccess.user_id == user_id,
            UserPlatformAccess.platform_id == platform_id,
            UserPlatformAccess.is_active == True
        )
    ).first()
    return access is not None


def grant_platform_access(db: Session, user_id: int, platform_id: int,
                          granted_by_user_id: int = None, role: str = "user") -> bool:
    """Grant user access to platform"""
    # Check if access already exists
    existing = db.query(UserPlatformAccess).filter(
        and_(
            UserPlatformAccess.user_id == user_id,
            UserPlatformAccess.platform_id == platform_id
        )
    ).first()

    if existing:
        # Reactivate if was revoked
        existing.is_active = True
        existing.role = role
        # Note: No more granted_by_user_id field
    else:
        # Create new access record - simplified structure
        access = UserPlatformAccess(
            user_id=user_id,
            platform_id=platform_id,
            role=role,
            is_active=True
            # Note: No more granted_by_user_id field
        )
        db.add(access)

    try:
        db.commit()
        return True
    except Exception:
        db.rollback()
        return False


def revoke_platform_access(db: Session, user_id: int, platform_id: int,
                           revoked_by_user_id: int) -> bool:
    """Revoke user access to platform"""
    access = db.query(UserPlatformAccess).filter(
        and_(
            UserPlatformAccess.user_id == user_id,
            UserPlatformAccess.platform_id == platform_id
        )
    ).first()

    if access:
        access.is_active = False
        access.revoked_at = datetime.now(timezone.utc)
        access.revoked_by_user_id = revoked_by_user_id
        db.commit()
        return True

    return False


def get_platform_users(db: Session, platform_id: int) -> list:
    """Get all users who have access to a platform"""
    accesses = db.query(UserPlatformAccess).filter(
        and_(
            UserPlatformAccess.platform_id == platform_id,
            UserPlatformAccess.is_active == True
        )
    ).all()

    return [(access.user_id, access.role) for access in accesses]