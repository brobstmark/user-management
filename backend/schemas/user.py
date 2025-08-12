"""
Pydantic schemas for user-related operations
"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, validator


class UserRegister(BaseModel):
    """
    Schema for user registration request
    """
    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., min_length=8, max_length=100, description="User's password")
    first_name: Optional[str] = Field(None, max_length=100, description="User's first name")
    last_name: Optional[str] = Field(None, max_length=100, description="User's last name")
    username: Optional[str] = Field(None, min_length=3, max_length=50, description="Username (optional)")

    @validator('username')
    def validate_username(cls, v):
        if v is not None:
            # Username can only contain letters, numbers, underscores, and hyphens
            import re
            if not re.match(r'^[a-zA-Z0-9_-]+$', v):
                raise ValueError('Username can only contain letters, numbers, underscores, and hyphens')
        return v

    @validator('email')
    def validate_email(cls, v):
        # Convert email to lowercase
        return v.lower()


class UserLogin(BaseModel):
    """
    Schema for user login request
    """
    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., description="User's password")

    @validator('email')
    def validate_email(cls, v):
        return v.lower()


class UserResponse(BaseModel):
    """
    Schema for user response (public user data)
    """
    id: int
    email: str
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    is_active: bool
    is_verified: bool
    created_at: datetime
    last_login: Optional[datetime] = None
    profile_picture_url: Optional[str] = None
    timezone: str
    language: str

    class Config:
        from_attributes = True  # For SQLAlchemy model conversion


class UserProfile(BaseModel):
    """
    Schema for detailed user profile (private data)
    """
    id: int
    email: str
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone: Optional[str] = None
    bio: Optional[str] = None
    profile_picture_url: Optional[str] = None
    timezone: str
    language: str
    is_active: bool
    is_verified: bool
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] = None

    class Config:
        from_attributes = True


class UserUpdate(BaseModel):
    """
    Schema for updating user profile
    """
    first_name: Optional[str] = Field(None, max_length=100)
    last_name: Optional[str] = Field(None, max_length=100)
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    phone: Optional[str] = Field(None, max_length=20)
    bio: Optional[str] = Field(None, max_length=1000)
    timezone: Optional[str] = Field(None, max_length=50)
    language: Optional[str] = Field(None, max_length=10)

    @validator('username')
    def validate_username(cls, v):
        if v is not None:
            import re
            if not re.match(r'^[a-zA-Z0-9_-]+$', v):
                raise ValueError('Username can only contain letters, numbers, underscores, and hyphens')
        return v


class PasswordChange(BaseModel):
    """
    Schema for password change request
    """
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., min_length=8, max_length=100, description="New password")


class PasswordReset(BaseModel):
    """
    Schema for password reset request
    """
    email: EmailStr = Field(..., description="Email address for password reset")

    @validator('email')
    def validate_email(cls, v):
        return v.lower()


class PasswordResetConfirm(BaseModel):
    """
    Schema for password reset confirmation
    """
    token: str = Field(..., description="Password reset token")
    new_password: str = Field(..., min_length=8, max_length=100, description="New password")

class ForgotUsername(BaseModel):
    """
    Schema for forgot username request
    """
    email: EmailStr = Field(..., description="Email address to send username to")

    @validator('email')
    def validate_email(cls, v):
        return v.lower()

class TokenResponse(BaseModel):
    """
    Schema for authentication token response
    """
    access_token: str
    token_type: str = "bearer"
    expires_in: int = Field(..., description="Token expiration time in seconds")


class MessageResponse(BaseModel):
    """
    Schema for simple message responses
    """
    message: str
    success: bool = True


# Example of how to use these schemas:
if __name__ == "__main__":
    # Test user registration schema
    user_data = {
        "email": "test@example.com",
        "password": "SecurePassword123!",
        "first_name": "John",
        "last_name": "Doe"
    }

    user_register = UserRegister(**user_data)
    print(f"Registration data: {user_register}")

    # Test validation
    try:
        invalid_user = UserRegister(email="invalid-email", password="short")
    except Exception as e:
        print(f"Validation error: {e}")