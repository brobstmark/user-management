"""
User Management Endpoints (Protected)
Enhanced with Secure Logging and Audit Trail
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from backend.config.database import get_db
from backend.core.dependencies import get_current_active_user, get_current_verified_user
from backend.schemas.user import UserProfile, UserUpdate, UserResponse, MessageResponse
from backend.crud.user import update_user, get_user_by_id
from backend.models.user import User

# 🔥 Import secure logging system
from backend.utils.logging import (
    get_api_logger,
    get_security_logger,
    log_security_event,
    log_audit_event
)

router = APIRouter()

# Initialize API logger for user management
logger = get_api_logger()


@router.get("/me", response_model=UserProfile)
async def get_current_user_profile(
        request: Request,
        current_user: User = Depends(get_current_active_user)
):
    """
    Get current user's complete profile

    Requires: Valid JWT token
    Returns: Complete user profile including private fields
    """
    client_ip = request.client.host if request.client else "unknown"

    logger.info("User profile accessed", extra={
        'action': 'get_profile',
        'user_id': current_user.id,
        'email': current_user.email,  # Will be redacted
        'ip_address': client_ip,
        'profile_type': 'self_complete'
    })

    log_audit_event(
        action="access_user_profile",
        resource="user_profile",
        result="success",
        user_id=current_user.id,
        ip_address=client_ip,
        profile_type="self_complete"
    )

    return current_user


@router.put("/me", response_model=UserProfile)
async def update_current_user_profile(
        user_updates: UserUpdate,
        request: Request,
        current_user: User = Depends(get_current_active_user),
        db: Session = Depends(get_db)
):
    """
    Update current user's profile

    Requires: Valid JWT token

    Updatable fields:
    - **first_name**: First name
    - **last_name**: Last name
    - **username**: Username (must be unique)
    - **phone**: Phone number
    - **bio**: User biography
    - **timezone**: User timezone
    - **language**: Preferred language
    """
    client_ip = request.client.host if request.client else "unknown"

    # Log the update attempt with details of what's being changed
    updated_fields = []
    if user_updates.first_name is not None:
        updated_fields.append("first_name")
    if user_updates.last_name is not None:
        updated_fields.append("last_name")
    if user_updates.username is not None:
        updated_fields.append("username")
    if user_updates.phone is not None:
        updated_fields.append("phone")
    if user_updates.bio is not None:
        updated_fields.append("bio")
    if user_updates.timezone is not None:
        updated_fields.append("timezone")
    if user_updates.language is not None:
        updated_fields.append("language")

    logger.info("Profile update attempt", extra={
        'action': 'update_profile',
        'user_id': current_user.id,
        'email': current_user.email,  # Will be redacted
        'ip_address': client_ip,
        'updated_fields': updated_fields,
        'field_count': len(updated_fields)
    })

    # Update the user
    result = update_user(db, current_user.id, user_updates)

    if not result["success"]:
        logger.warning("Profile update failed", extra={
            'action': 'update_profile',
            'user_id': current_user.id,
            'email': current_user.email,  # Will be redacted
            'ip_address': client_ip,
            'errors': result["errors"],
            'updated_fields': updated_fields
        })

        log_security_event(
            event_type="profile_update",
            action="update_profile",
            result="failure",
            user_id=current_user.id,
            ip_address=client_ip,
            failure_reason="validation_failure"
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": "Profile update failed",
                "errors": result["errors"]
            }
        )

    # Log successful update
    logger.info("Profile updated successfully", extra={
        'action': 'update_profile',
        'user_id': current_user.id,
        'email': current_user.email,  # Will be redacted
        'ip_address': client_ip,
        'updated_fields': updated_fields,
        'field_count': len(updated_fields)
    })

    log_audit_event(
        action="update_user_profile",
        resource="user_profile",
        result="success",
        user_id=current_user.id,
        ip_address=client_ip,
        updated_fields=updated_fields
    )

    # Log security event for sensitive field changes
    sensitive_fields = ['username', 'phone']
    sensitive_changes = [field for field in updated_fields if field in sensitive_fields]
    if sensitive_changes:
        log_security_event(
            event_type="profile_update",
            action="update_sensitive_fields",
            result="success",
            user_id=current_user.id,
            ip_address=client_ip,
            changed_fields=sensitive_changes
        )

    return result["user"]


@router.get("/me/public", response_model=UserResponse)
async def get_current_user_public_profile(
        request: Request,
        current_user: User = Depends(get_current_active_user)
):
    """
    Get current user's public profile data

    Requires: Valid JWT token
    Returns: Public user data (excludes sensitive fields)
    """
    client_ip = request.client.host if request.client else "unknown"

    logger.debug("Public profile accessed", extra={
        'action': 'get_public_profile',
        'user_id': current_user.id,
        'email': current_user.email,  # Will be redacted
        'ip_address': client_ip,
        'profile_type': 'self_public'
    })

    return current_user


@router.delete("/me", response_model=MessageResponse)
async def deactivate_current_user_account(
        request: Request,
        current_user: User = Depends(get_current_active_user),
        db: Session = Depends(get_db)
):
    """
    Deactivate current user's account

    Requires: Valid JWT token
    Note: This deactivates the account but doesn't delete data
    """
    client_ip = request.client.host if request.client else "unknown"

    logger.warning("Account deactivation requested", extra={
        'action': 'deactivate_account',
        'user_id': current_user.id,
        'email': current_user.email,  # Will be redacted
        'ip_address': client_ip
    })

    from backend.crud.user import deactivate_user

    success = deactivate_user(db, current_user.id)

    if not success:
        logger.error("Account deactivation failed", extra={
            'action': 'deactivate_account',
            'user_id': current_user.id,
            'email': current_user.email,  # Will be redacted
            'ip_address': client_ip,
            'failure_reason': 'database_error'
        })

        log_security_event(
            event_type="account_management",
            action="deactivate_account",
            result="failure",
            user_id=current_user.id,
            ip_address=client_ip,
            failure_reason="database_error"
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to deactivate account"
        )

    # Log successful deactivation (this is a major security event)
    logger.warning("Account deactivated successfully", extra={
        'action': 'deactivate_account',
        'user_id': current_user.id,
        'email': current_user.email,  # Will be redacted
        'ip_address': client_ip
    })

    log_security_event(
        event_type="account_management",
        action="deactivate_account",
        result="success",
        user_id=current_user.id,
        ip_address=client_ip
    )

    log_audit_event(
        action="deactivate_user_account",
        resource="user_account",
        result="success",
        user_id=current_user.id,
        ip_address=client_ip
    )

    return {
        "message": "Account successfully deactivated",
        "success": True
    }


@router.get("/profile/{user_id}", response_model=UserResponse)
async def get_user_public_profile(
        user_id: int,
        request: Request,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_active_user)
):
    """
    Get another user's public profile

    Requires: Valid JWT token
    Returns: Public profile of specified user
    """
    client_ip = request.client.host if request.client else "unknown"

    logger.info("User profile lookup attempt", extra={
        'action': 'get_other_profile',
        'viewer_user_id': current_user.id,
        'target_user_id': user_id,
        'viewer_email': current_user.email,  # Will be redacted
        'ip_address': client_ip
    })

    user = get_user_by_id(db, user_id)

    if not user:
        logger.info("Profile lookup failed - user not found", extra={
            'action': 'get_other_profile',
            'viewer_user_id': current_user.id,
            'target_user_id': user_id,
            'ip_address': client_ip,
            'failure_reason': 'user_not_found'
        })

        log_security_event(
            event_type="profile_access",
            action="get_other_profile",
            result="failure",
            viewer_user_id=current_user.id,
            target_user_id=user_id,
            ip_address=client_ip,
            failure_reason="user_not_found"
        )

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    if not user.is_active:
        logger.info("Profile lookup failed - user inactive", extra={
            'action': 'get_other_profile',
            'viewer_user_id': current_user.id,
            'target_user_id': user_id,
            'ip_address': client_ip,
            'failure_reason': 'user_inactive'
        })

        log_security_event(
            event_type="profile_access",
            action="get_other_profile",
            result="failure",
            viewer_user_id=current_user.id,
            target_user_id=user_id,
            ip_address=client_ip,
            failure_reason="user_inactive"
        )

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Log successful profile access
    logger.info("User profile accessed successfully", extra={
        'action': 'get_other_profile',
        'viewer_user_id': current_user.id,
        'target_user_id': user_id,
        'target_email': user.email,  # Will be redacted
        'ip_address': client_ip
    })

    log_audit_event(
        action="access_other_user_profile",
        resource="user_profile",
        result="success",
        viewer_user_id=current_user.id,
        target_user_id=user_id,
        ip_address=client_ip
    )

    return user


@router.get("/verify-token")
async def verify_jwt_token(
        request: Request,
        current_user: User = Depends(get_current_active_user)
):
    """
    Verify JWT token validity

    Requires: Valid JWT token
    Returns: Token status and user info
    """
    client_ip = request.client.host if request.client else "unknown"

    logger.debug("Token verification requested", extra={
        'action': 'verify_token',
        'user_id': current_user.id,
        'email': current_user.email,  # Will be redacted
        'ip_address': client_ip,
        'is_active': current_user.is_active,
        'is_verified': current_user.is_verified
    })

    return {
        "valid": True,
        "user_id": current_user.id,
        "email": current_user.email,
        "is_active": current_user.is_active,
        "is_verified": current_user.is_verified
    }


# Example of endpoint requiring email verification
@router.get("/premium-feature", response_model=MessageResponse)
async def premium_feature_example(
        request: Request,
        current_user: User = Depends(get_current_verified_user)
):
    """
    Example endpoint requiring verified email

    Requires: Valid JWT token + verified email
    """
    client_ip = request.client.host if request.client else "unknown"

    logger.info("Premium feature accessed", extra={
        'action': 'access_premium_feature',
        'user_id': current_user.id,
        'email': current_user.email,  # Will be redacted
        'ip_address': client_ip,
        'feature': 'premium_example',
        'verification_required': True
    })

    log_audit_event(
        action="access_premium_feature",
        resource="premium_service",
        result="success",
        user_id=current_user.id,
        ip_address=client_ip,
        feature="premium_example"
    )

    # Log premium feature usage for business analytics
    log_security_event(
        event_type="feature_access",
        action="premium_feature_access",
        result="success",
        user_id=current_user.id,
        ip_address=client_ip,
        feature="premium_example",
        verification_status="verified"
    )

    return {
        "message": f"Welcome to premium features, {current_user.first_name or current_user.email}!",
        "success": True
    }