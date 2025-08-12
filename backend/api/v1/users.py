"""
User Management Endpoints (Protected)
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.config.database import get_db
from backend.core.dependencies import get_current_active_user, get_current_verified_user
from backend.schemas.user import UserProfile, UserUpdate, UserResponse, MessageResponse
from backend.crud.user import update_user, get_user_by_id
from backend.models.user import User

router = APIRouter()


@router.get("/me", response_model=UserProfile)
async def get_current_user_profile(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get current user's complete profile

    Requires: Valid JWT token
    Returns: Complete user profile including private fields
    """
    return current_user


@router.put("/me", response_model=UserProfile)
async def update_current_user_profile(
    user_updates: UserUpdate,
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
    # Update the user
    result = update_user(db, current_user.id, user_updates)

    if not result["success"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": "Profile update failed",
                "errors": result["errors"]
            }
        )

    return result["user"]


@router.get("/me/public", response_model=UserResponse)
async def get_current_user_public_profile(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get current user's public profile data

    Requires: Valid JWT token
    Returns: Public user data (excludes sensitive fields)
    """
    return current_user


@router.delete("/me", response_model=MessageResponse)
async def deactivate_current_user_account(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Deactivate current user's account

    Requires: Valid JWT token
    Note: This deactivates the account but doesn't delete data
    """
    from backend.crud.user import deactivate_user

    success = deactivate_user(db, current_user.id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to deactivate account"
        )

    return {
        "message": "Account successfully deactivated",
        "success": True
    }


@router.get("/profile/{user_id}", response_model=UserResponse)
async def get_user_public_profile(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get another user's public profile

    Requires: Valid JWT token
    Returns: Public profile of specified user
    """
    user = get_user_by_id(db, user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return user


@router.get("/verify-token")
async def verify_jwt_token(
    current_user: User = Depends(get_current_active_user)
):
    """
    Verify JWT token validity

    Requires: Valid JWT token
    Returns: Token status and user info
    """
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
    current_user: User = Depends(get_current_verified_user)
):
    """
    Example endpoint requiring verified email

    Requires: Valid JWT token + verified email
    """
    return {
        "message": f"Welcome to premium features, {current_user.first_name or current_user.email}!",
        "success": True
    }