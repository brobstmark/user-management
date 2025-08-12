"""
Authentication Endpoints with Email Verification
"""
from datetime import timedelta, datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.config.database import get_db
from backend.config.settings import settings
from backend.core.dependencies import get_current_active_user
from backend.schemas.user import (
    UserRegister,
    UserLogin,
    UserResponse,
    TokenResponse,
    MessageResponse
)
from backend.crud.user import create_user, get_user_by_email, update_last_login
from backend.core.security import (
    verify_password,
    create_access_token,
    create_email_verification_token,
    verify_email_verification_token
)
from backend.models.user import User
from backend.schemas.user import PasswordReset, PasswordResetConfirm, ForgotUsername, PasswordChange
from backend.crud.user import set_password_reset_token, reset_password_with_token, change_password
from backend.core.security import create_password_reset_token, verify_password_reset_token
from backend.services.email_service import send_password_reset_email, send_username_recovery_email, send_password_changed_notification
router = APIRouter()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
        user_data: UserRegister,
        db: Session = Depends(get_db)
):
    """
    Register a new user account and send verification email

    - **email**: Valid email address (will be converted to lowercase)
    - **password**: Strong password (min 8 chars, uppercase, lowercase, number, special char)
    - **first_name**: Optional first name
    - **last_name**: Optional last name
    - **username**: Optional username (alphanumeric, underscore, hyphen only)

    Returns the created user data and sends verification email
    """
    # Create the user
    result = create_user(db, user_data)

    if not result["success"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": "Registration failed",
                "errors": result["errors"]
            }
        )

    user = result["user"]

    # Generate and save verification token
    verification_token = create_email_verification_token(user.email)
    user.email_verification_token = verification_token
    user.email_verification_sent_at = datetime.now(timezone.utc)
    db.commit()

    # Send verification email
    from backend.services.email_service import send_verification_email
    user_name = user.first_name or user.email.split('@')[0]

    try:
        await send_verification_email(
            user_email=user.email,
            user_name=user_name,
            verification_token=verification_token
        )
        print(f"✅ Verification email sent to {user.email}")
    except Exception as e:
        print(f"⚠️ Failed to send verification email: {e}")
        # Don't fail registration if email sending fails

    return user


@router.post("/login", response_model=TokenResponse)
async def login_user(
        login_data: UserLogin,
        db: Session = Depends(get_db)
):
    """
    User login endpoint

    - **email**: User's email address
    - **password**: User's password

    Returns JWT access token for authentication
    """
    # Get user by email
    user = get_user_by_email(db, login_data.email)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verify password
    if not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if user is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Account is deactivated"
        )

    # Update last login time
    update_last_login(db, user.id)

    # Create access token
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email, "user_id": user.id},
        expires_delta=access_token_expires
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60  # Convert to seconds
    }


@router.post("/logout", response_model=MessageResponse)
async def logout_user():
    """
    User logout endpoint

    Note: With JWT tokens, logout is typically handled client-side
    by removing the token. This endpoint is provided for consistency
    and can be extended for token blacklisting if needed.
    """
    return {
        "message": "Successfully logged out",
        "success": True
    }


@router.post("/send-verification", response_model=MessageResponse)
async def send_verification_email_endpoint(
        current_user: User = Depends(get_current_active_user),
        db: Session = Depends(get_db)
):
    """
    Send email verification to current user

    Requires: Valid JWT token
    """
    # Check if already verified
    if current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is already verified"
        )

    # Generate verification token
    verification_token = create_email_verification_token(current_user.email)

    # Save token to database
    current_user.email_verification_token = verification_token
    current_user.email_verification_sent_at = datetime.now(timezone.utc)
    db.commit()

    # Send verification email
    from backend.services.email_service import send_verification_email
    user_name = current_user.first_name or current_user.email.split('@')[0]

    email_sent = await send_verification_email(
        user_email=current_user.email,
        user_name=user_name,
        verification_token=verification_token
    )

    if not email_sent:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send verification email"
        )

    return {
        "message": "Verification email sent successfully",
        "success": True
    }


@router.get("/verify-email", response_model=MessageResponse)
async def verify_email_endpoint(
        token: str,
        db: Session = Depends(get_db)
):
    """
    Verify user's email address using verification token

    Args:
        token: Email verification token (from email link)
    """
    # Verify the token
    email = verify_email_verification_token(token)

    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token"
        )

    # Find user by email
    user = get_user_by_email(db, email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Check if token matches the one in database
    if user.email_verification_token != token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification token"
        )

    # Check if already verified
    if user.is_verified:
        return {
            "message": "Email is already verified",
            "success": True
        }

    # Mark email as verified
    from backend.crud.user import verify_user_email
    success = verify_user_email(db, user.id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify email"
        )

    return {
        "message": "Email verified successfully! Your account is now fully activated.",
        "success": True
    }


@router.get("/verification-status", response_model=dict)
async def get_verification_status(
        current_user: User = Depends(get_current_active_user)
):
    """
    Get current user's email verification status

    Requires: Valid JWT token
    """
    return {
        "email": current_user.email,
        "is_verified": current_user.is_verified,
        "verification_sent_at": current_user.email_verification_sent_at.isoformat() if current_user.email_verification_sent_at else None
    }

@router.post("/forgot-password", response_model=MessageResponse)
async def forgot_password(
        request: PasswordReset,
        db: Session = Depends(get_db)
):
    """
    Request password reset - sends email with reset link

    Args:
        request: Password reset request with email

    Returns:
        Success message (always returns success to prevent email enumeration)
    """
    # Always return success message to prevent email enumeration attacks
    success_message = "If the email address exists, password reset instructions have been sent"

    # Find user by email
    user = get_user_by_email(db, request.email)

    if not user:
        # Don't reveal that email doesn't exist
        return {
            "message": success_message,
            "success": True
        }

    if not user.is_active:
        # Don't reveal that account is inactive
        return {
            "message": success_message,
            "success": True
        }

    try:
        # Generate password reset token
        reset_token = create_password_reset_token(user.email)

        # Save token to database
        token_saved = set_password_reset_token(db, user.id, reset_token)

        if not token_saved:
            print(f"⚠️ Failed to save reset token for user {user.email}")
            return {
                "message": success_message,
                "success": True
            }

        # Send password reset email
        user_name = user.first_name or user.email.split('@')[0]
        email_sent = await send_password_reset_email(
            user_email=user.email,
            user_name=user_name,
            reset_token=reset_token
        )

        if email_sent:
            print(f"✅ Password reset email sent to {user.email}")
        else:
            print(f"⚠️ Failed to send reset email to {user.email}")

    except Exception as e:
        print(f"❌ Error in forgot password for {request.email}: {e}")

    return {
        "message": success_message,
        "success": True
    }


@router.post("/reset-password", response_model=MessageResponse)
async def reset_password(
        request: PasswordResetConfirm,
        db: Session = Depends(get_db)
):
    """
    Reset password using reset token

    Args:
        request: Password reset confirmation with token and new password

    Returns:
        Success/error message
    """
    # Verify the reset token
    email = verify_password_reset_token(request.token)

    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token"
        )

    # Reset the password
    result = reset_password_with_token(db, request.token, request.new_password)

    if not result["success"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": "Password reset failed",
                "errors": result["errors"]
            }
        )

    # Send confirmation email
    try:
        user = get_user_by_email(db, email)
        if user:
            user_name = user.first_name or user.email.split('@')[0]
            await send_password_changed_notification(user.email, user_name)
    except Exception as e:
        print(f"⚠️ Failed to send password changed notification: {e}")

    return {
        "message": "Password has been reset successfully. You can now log in with your new password.",
        "success": True
    }


@router.post("/forgot-username", response_model=MessageResponse)
async def forgot_username(
        request: ForgotUsername,
        db: Session = Depends(get_db)
):
    """
    Send username to user's email address

    Args:
        request: Forgot username request with email

    Returns:
        Success message (always returns success to prevent email enumeration)
    """
    # Always return success message to prevent email enumeration attacks
    success_message = "If the email address exists, username recovery instructions have been sent"

    # Find user by email
    user = get_user_by_email(db, request.email)

    if not user:
        # Don't reveal that email doesn't exist
        return {
            "message": success_message,
            "success": True
        }

    if not user.is_active:
        # Don't reveal that account is inactive
        return {
            "message": success_message,
            "success": True
        }

    try:
        # Send username recovery email
        user_name = user.first_name or user.email.split('@')[0]
        username = user.username or user.email  # Use email if no username set

        email_sent = await send_username_recovery_email(
            user_email=user.email,
            user_name=user_name,
            username=username
        )

        if email_sent:
            print(f"✅ Username recovery email sent to {user.email}")
        else:
            print(f"⚠️ Failed to send username recovery email to {user.email}")

    except Exception as e:
        print(f"❌ Error in username recovery for {request.email}: {e}")

    return {
        "message": success_message,
        "success": True
    }


@router.post("/change-password", response_model=MessageResponse)
async def change_password_endpoint(
        request: PasswordChange,
        current_user: User = Depends(get_current_active_user),
        db: Session = Depends(get_db)
):
    """
    Change user password (requires current password)

    Args:
        request: Password change request with current and new password
        current_user: Currently authenticated user

    Returns:
        Success/error message
    """
    # Change the password
    result = change_password(
        db,
        current_user.id,
        request.current_password,
        request.new_password
    )

    if not result["success"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": "Password change failed",
                "errors": result["errors"]
            }
        )

    # Send confirmation email
    try:
        user_name = current_user.first_name or current_user.email.split('@')[0]
        await send_password_changed_notification(current_user.email, user_name)
    except Exception as e:
        print(f"⚠️ Failed to send password changed notification: {e}")

    return {
        "message": "Password has been changed successfully.",
        "success": True
    }