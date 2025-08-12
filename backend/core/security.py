"""
Security utilities for password hashing and JWT token management
"""
from datetime import datetime, timedelta, timezone
from typing import Optional, Union

from jose import JWTError, jwt
from passlib.context import CryptContext

from backend.config.settings import settings

# Password hashing context using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt

    Args:
        password: Plain text password

    Returns:
        Hashed password string
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against a hashed password

    Args:
        plain_password: Plain text password to verify
        hashed_password: Stored hashed password

    Returns:
        True if password matches, False otherwise
    """
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token

    Args:
        data: Dictionary of data to encode in the token (usually user info)
        expires_delta: Optional custom expiration time

    Returns:
        Encoded JWT token string
    """
    to_encode = data.copy()

    # Set expiration time
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})

    # Create and return the JWT token
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def verify_token(token: str) -> Optional[dict]:
    """
    Verify and decode a JWT token

    Args:
        token: JWT token string to verify

    Returns:
        Decoded token payload if valid, None if invalid
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

        # Check if token has expired
        exp = payload.get("exp")
        if exp is None:
            return None

        # Verify expiration
        if datetime.now(timezone.utc) > datetime.fromtimestamp(exp, tz=timezone.utc):
            return None

        return payload

    except JWTError:
        return None


def create_password_reset_token(email: str) -> str:
    """
    Create a JWT token for password reset

    Args:
        email: User's email address

    Returns:
        JWT token for password reset
    """
    # Password reset tokens expire in 1 hour
    delta = timedelta(hours=1)
    return create_access_token(
        data={"sub": email, "type": "password_reset"},
        expires_delta=delta
    )


def create_email_verification_token(email: str) -> str:
    """
    Create a JWT token for email verification

    Args:
        email: User's email address

    Returns:
        JWT token for email verification
    """
    # Email verification tokens expire in 24 hours
    delta = timedelta(hours=24)
    return create_access_token(
        data={"sub": email, "type": "email_verification"},
        expires_delta=delta
    )


def verify_password_reset_token(token: str) -> Optional[str]:
    """
    Verify a password reset token and extract email

    Args:
        token: Password reset token

    Returns:
        Email address if token is valid, None otherwise
    """
    payload = verify_token(token)
    if payload and payload.get("type") == "password_reset":
        return payload.get("sub")
    return None


def verify_email_verification_token(token: str) -> Optional[str]:
    """
    Verify an email verification token and extract email

    Args:
        token: Email verification token

    Returns:
        Email address if token is valid, None otherwise
    """
    payload = verify_token(token)
    if payload and payload.get("type") == "email_verification":
        return payload.get("sub")
    return None


def validate_password_strength(password: str) -> dict:
    """
    Validate password strength and return feedback

    Args:
        password: Password to validate

    Returns:
        Dictionary with 'valid' boolean and 'errors' list
    """
    errors = []

    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")

    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")

    if not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")

    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one number")

    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        errors.append("Password must contain at least one special character")

    return {
        "valid": len(errors) == 0,
        "errors": errors
    }


# Example usage and testing functions (for development)
if __name__ == "__main__":
    # Test password hashing
    password = "MySecurePassword123!"
    hashed = hash_password(password)
    print(f"Original: {password}")
    print(f"Hashed: {hashed}")
    print(f"Verification: {verify_password(password, hashed)}")

    # Test JWT tokens
    token = create_access_token({"sub": "user@example.com", "user_id": 1})
    print(f"Token: {token}")
    print(f"Decoded: {verify_token(token)}")

    # Test password strength
    print(f"Password strength: {validate_password_strength(password)}")