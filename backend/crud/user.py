"""
CRUD operations for User model
"""
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from backend.models.user import User
from backend.schemas.user import UserRegister, UserUpdate
from backend.core.security import hash_password, verify_password, validate_password_strength


def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
    """
    Get user by ID

    Args:
        db: Database session
        user_id: User ID

    Returns:
        User object or None if not found
    """
    return db.query(User).filter(User.id == user_id).first()


def get_user_by_email(db: Session, email: str) -> Optional[User]:
    """
    Get user by email address

    Args:
        db: Database session
        email: Email address

    Returns:
        User object or None if not found
    """
    return db.query(User).filter(User.email == email.lower()).first()


def get_user_by_username(db: Session, username: str) -> Optional[User]:
    """
    Get user by username

    Args:
        db: Database session
        username: Username

    Returns:
        User object or None if not found
    """
    return db.query(User).filter(User.username == username).first()


def create_user(db: Session, user_data: UserRegister) -> dict:
    """
    Create a new user

    Args:
        db: Database session
        user_data: User registration data

    Returns:
        Dictionary with 'user' and 'success' keys
    """
    # Validate password strength
    password_check = validate_password_strength(user_data.password)
    if not password_check["valid"]:
        return {
            "user": None,
            "success": False,
            "errors": password_check["errors"]
        }

    # Check if email already exists
    if get_user_by_email(db, user_data.email):
        return {
            "user": None,
            "success": False,
            "errors": ["Email address already registered"]
        }

    # Check if username already exists (if provided)
    if user_data.username and get_user_by_username(db, user_data.username):
        return {
            "user": None,
            "success": False,
            "errors": ["Username already taken"]
        }

    try:
        # Hash the password
        hashed_password = hash_password(user_data.password)

        # Create user object
        db_user = User(
            email=user_data.email.lower(),
            username=user_data.username,
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            hashed_password=hashed_password,
            is_active=True,
            is_verified=False,  # Require email verification
            is_superuser=False,
            password_changed_at=datetime.now(timezone.utc)
        )

        # Add to database
        db.add(db_user)
        db.commit()
        db.refresh(db_user)

        return {
            "user": db_user,
            "success": True,
            "errors": []
        }

    except IntegrityError as e:
        db.rollback()
        # Handle unique constraint violations
        if "email" in str(e).lower():
            error_message = "Email address already registered"
        elif "username" in str(e).lower():
            error_message = "Username already taken"
        else:
            error_message = "Registration failed due to a database constraint"

        return {
            "user": None,
            "success": False,
            "errors": [error_message]
        }

    except Exception as e:
        db.rollback()
        return {
            "user": None,
            "success": False,
            "errors": [f"Registration failed: {str(e)}"]
        }


def update_user(db: Session, user_id: int, user_data: UserUpdate) -> dict:
    """
    Update user profile

    Args:
        db: Database session
        user_id: User ID to update
        user_data: Updated user data

    Returns:
        Dictionary with 'user' and 'success' keys
    """
    try:
        # Get existing user
        db_user = get_user_by_id(db, user_id)
        if not db_user:
            return {
                "user": None,
                "success": False,
                "errors": ["User not found"]
            }

        # Check if username is taken by another user
        if user_data.username and user_data.username != db_user.username:
            existing_user = get_user_by_username(db, user_data.username)
            if existing_user and existing_user.id != user_id:
                return {
                    "user": None,
                    "success": False,
                    "errors": ["Username already taken"]
                }

        # Update fields that are provided
        update_data = user_data.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(db_user, field, value)

        # Update the updated_at timestamp
        db_user.updated_at = datetime.now(timezone.utc)

        db.commit()
        db.refresh(db_user)

        return {
            "user": db_user,
            "success": True,
            "errors": []
        }

    except IntegrityError as e:
        db.rollback()
        if "username" in str(e).lower():
            error_message = "Username already taken"
        else:
            error_message = "Update failed due to a database constraint"

        return {
            "user": None,
            "success": False,
            "errors": [error_message]
        }

    except Exception as e:
        db.rollback()
        return {
            "user": None,
            "success": False,
            "errors": [f"Update failed: {str(e)}"]
        }


def update_last_login(db: Session, user_id: int) -> bool:
    """
    Update user's last login timestamp

    Args:
        db: Database session
        user_id: User ID

    Returns:
        True if successful, False otherwise
    """
    try:
        db_user = get_user_by_id(db, user_id)
        if db_user:
            db_user.last_login = datetime.now(timezone.utc)
            db.commit()
            return True
        return False
    except Exception:
        db.rollback()
        return False


def deactivate_user(db: Session, user_id: int) -> bool:
    """
    Deactivate a user account

    Args:
        db: Database session
        user_id: User ID

    Returns:
        True if successful, False otherwise
    """
    try:
        db_user = get_user_by_id(db, user_id)
        if db_user:
            db_user.is_active = False
            db.commit()
            return True
        return False
    except Exception:
        db.rollback()
        return False


def verify_user_email(db: Session, user_id: int) -> bool:
    """
    Mark user's email as verified

    Args:
        db: Database session
        user_id: User ID

    Returns:
        True if successful, False otherwise
    """
    try:
        db_user = get_user_by_id(db, user_id)
        if db_user:
            db_user.is_verified = True
            db_user.email_verification_token = None
            db_user.email_verification_sent_at = None
            db.commit()
            return True
        return False
    except Exception:
        db.rollback()
        return False


def count_users(db: Session) -> int:
    """
    Count total number of users

    Args:
        db: Database session

    Returns:
        Number of users
    """
    return db.query(User).count()


def get_users_paginated(db: Session, skip: int = 0, limit: int = 100):
    """
    Get users with pagination

    Args:
        db: Database session
        skip: Number of users to skip
        limit: Maximum number of users to return

    Returns:
        List of User objects
    """
    return db.query(User).offset(skip).limit(limit).all()


def set_password_reset_token(db: Session, user_id: int, reset_token: str) -> bool:
    """
    Set password reset token for user

    Args:
        db: Database session
        user_id: User ID
        reset_token: Password reset token

    Returns:
        True if successful, False otherwise
    """
    try:
        db_user = get_user_by_id(db, user_id)
        if db_user:
            db_user.password_reset_token = reset_token
            db_user.password_reset_sent_at = datetime.now(timezone.utc)
            db.commit()
            return True
        return False
    except Exception:
        db.rollback()
        return False


def reset_password_with_token(db: Session, reset_token: str, new_password: str) -> dict:
    """
    Reset user password using reset token

    Args:
        db: Database session
        reset_token: Password reset token
        new_password: New password

    Returns:
        Dictionary with 'success' and 'errors' keys
    """
    # Import here to avoid circular imports
    from backend.core.security import hash_password, validate_password_strength

    # Validate new password strength
    password_check = validate_password_strength(new_password)
    if not password_check["valid"]:
        return {
            "success": False,
            "errors": password_check["errors"]
        }

    try:
        # Find user with this reset token
        db_user = db.query(User).filter(User.password_reset_token == reset_token).first()

        if not db_user:
            return {
                "success": False,
                "errors": ["Invalid or expired reset token"]
            }

        # JWT token expiration is already handled by verify_password_reset_token()
        # No need for additional database time checks

        # Hash new password
        hashed_password = hash_password(new_password)

        # Update password and clear reset token
        db_user.hashed_password = hashed_password
        db_user.password_changed_at = datetime.now(timezone.utc)
        db_user.password_reset_token = None
        db_user.password_reset_sent_at = None
        db_user.failed_login_attempts = 0  # Reset failed attempts
        db_user.account_locked_until = None  # Unlock account if it was locked

        db.commit()

        return {
            "success": True,
            "errors": []
        }

    except Exception as e:
        db.rollback()
        return {
            "success": False,
            "errors": [f"Password reset failed: {str(e)}"]
        }


def change_password(db: Session, user_id: int, current_password: str, new_password: str) -> dict:
    """
    Change user password (requires current password)

    Args:
        db: Database session
        user_id: User ID
        current_password: Current password for verification
        new_password: New password

    Returns:
        Dictionary with 'success' and 'errors' keys
    """
    # Validate new password strength
    password_check = validate_password_strength(new_password)
    if not password_check["valid"]:
        return {
            "success": False,
            "errors": password_check["errors"]
        }

    try:
        db_user = get_user_by_id(db, user_id)
        if not db_user:
            return {
                "success": False,
                "errors": ["User not found"]
            }

        # Verify current password
        if not verify_password(current_password, db_user.hashed_password):
            return {
                "success": False,
                "errors": ["Current password is incorrect"]
            }

        # Hash new password
        hashed_password = hash_password(new_password)

        # Update password
        db_user.hashed_password = hashed_password
        db_user.password_changed_at = datetime.now(timezone.utc)

        db.commit()

        return {
            "success": True,
            "errors": []
        }

    except Exception as e:
        db.rollback()
        return {
            "success": False,
            "errors": [f"Password change failed: {str(e)}"]
        }