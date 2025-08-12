"""
FastAPI dependencies for authentication and user management
"""
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from backend.config.database import get_db
from backend.core.security import verify_token
from backend.models.user import User

# HTTP Bearer token security scheme
security = HTTPBearer()


async def get_current_user_from_token(
        credentials: HTTPAuthorizationCredentials = Depends(security),
        db: Session = Depends(get_db)
) -> User:
    """
    Dependency to get the current user from JWT token

    Args:
        credentials: HTTP Bearer token from request header
        db: Database session

    Returns:
        User object if token is valid

    Raises:
        HTTPException: If token is invalid or user not found
    """
    # Define the exception for invalid credentials
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Extract token from credentials
        token = credentials.credentials

        # Verify and decode the token
        payload = verify_token(token)
        if payload is None:
            raise credentials_exception

        # Extract user email from token
        user_email: str = payload.get("sub")
        if user_email is None:
            raise credentials_exception

    except Exception:
        raise credentials_exception

    # Get user from database
    user = db.query(User).filter(User.email == user_email).first()
    if user is None:
        raise credentials_exception

    return user


async def get_current_active_user(
        current_user: User = Depends(get_current_user_from_token)
) -> User:
    """
    Dependency to get current user and ensure they are active

    Args:
        current_user: User from get_current_user_from_token

    Returns:
        User object if active

    Raises:
        HTTPException: If user is inactive
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user


async def get_current_verified_user(
        current_user: User = Depends(get_current_active_user)
) -> User:
    """
    Dependency to get current user and ensure they are verified

    Args:
        current_user: User from get_current_active_user

    Returns:
        User object if verified

    Raises:
        HTTPException: If user is not verified
    """
    if not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email not verified"
        )
    return current_user


async def get_current_superuser(
        current_user: User = Depends(get_current_active_user)
) -> User:
    """
    Dependency to get current user and ensure they are a superuser

    Args:
        current_user: User from get_current_active_user

    Returns:
        User object if superuser

    Raises:
        HTTPException: If user is not a superuser
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user


def get_optional_current_user(
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
        db: Session = Depends(get_db)
) -> Optional[User]:
    """
    Optional dependency to get current user (doesn't raise error if no token)

    Args:
        credentials: Optional HTTP Bearer token
        db: Database session

    Returns:
        User object if valid token provided, None otherwise
    """
    if credentials is None:
        return None

    try:
        # Extract and verify token
        token = credentials.credentials
        payload = verify_token(token)

        if payload is None:
            return None

        # Extract user email
        user_email: str = payload.get("sub")
        if user_email is None:
            return None

        # Get user from database
        user = db.query(User).filter(User.email == user_email).first()
        return user

    except Exception:
        return None