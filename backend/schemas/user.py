"""
Pydantic schemas for user-related operations
Production-ready with comprehensive security validations
"""
import re
import html
import pytz
from datetime import datetime
from typing import Optional, Set, Any, Dict
from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator


# Security constants
ALLOWED_LANGUAGES = {
    'en', 'es', 'fr', 'de', 'it', 'pt', 'ru', 'zh', 'ja', 'ko', 'ar', 'hi'
}

BLOCKED_PATTERNS = [
    r'<script[^>]*>.*?</script>',
    r'javascript:',
    r'vbscript:',
    r'onload=',
    r'onerror=',
    r'onclick=',
    r'onmouseover=',
    r'<iframe[^>]*>.*?</iframe>',
    r'<object[^>]*>.*?</object>',
    r'<embed[^>]*>.*?</embed>',
]

def sanitize_text(text: str) -> str:
    """
    Sanitize text input to prevent XSS attacks

    Args:
        text: Raw text input

    Returns:
        Sanitized text safe for storage and display
    """
    if not text:
        return text

    # HTML encode to prevent XSS
    sanitized = html.escape(text.strip())

    # Check for blocked patterns
    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, sanitized, re.IGNORECASE):
            raise ValueError("Input contains potentially malicious content")

    return sanitized

def validate_password_strength(password: str) -> str:
    """
    Validate password strength for production security

    Requirements:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    - No common passwords

    Args:
        password: Password to validate

    Returns:
        Password if valid

    Raises:
        ValueError: If password doesn't meet requirements
    """
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")

    if len(password) > 100:
        raise ValueError("Password too long (max 100 characters)")

    # Check for character requirements
    if not re.search(r'[A-Z]', password):
        raise ValueError("Password must contain at least one uppercase letter")

    if not re.search(r'[a-z]', password):
        raise ValueError("Password must contain at least one lowercase letter")

    if not re.search(r'\d', password):
        raise ValueError("Password must contain at least one digit")

    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>?]', password):
        raise ValueError("Password must contain at least one special character")

    # Check for common weak passwords
    common_passwords = {
        'password', 'password123', '12345678', 'qwerty', 'abc123',
        'password1', '123456789', 'welcome', 'admin', 'letmein'
    }

    if password.lower() in common_passwords:
        raise ValueError("Password is too common, please choose a stronger password")

    # Check for sequential characters
    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)', password.lower()):
        raise ValueError("Password should not contain sequential characters")

    return password

def validate_phone_number(phone: str) -> str:
    """
    Validate phone number format

    Accepts formats:
    - +1-234-567-8900
    - (234) 567-8900
    - 234-567-8900
    - 234.567.8900
    - 2345678900

    Args:
        phone: Phone number to validate

    Returns:
        Sanitized phone number
    """
    if not phone:
        return phone

    # Remove all non-digit characters except + for country codes
    cleaned = re.sub(r'[^\d+]', '', phone)

    # Validate format
    if not re.match(r'^\+?1?[2-9]\d{2}[2-9]\d{2}\d{4}$', cleaned):
        raise ValueError("Invalid phone number format")

    return phone.strip()


class UserRegister(BaseModel):
    """
    Schema for user registration request with enhanced security
    """
    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., description="User's password")
    first_name: Optional[str] = Field(None, max_length=100, description="User's first name")
    last_name: Optional[str] = Field(None, max_length=100, description="User's last name")
    username: Optional[str] = Field(None, min_length=3, max_length=50, description="Username (optional)")

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        return validate_password_strength(v)

    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        if v is not None:
            # Sanitize and validate username
            v = sanitize_text(v)

            # Username restrictions for security
            if not re.match(r'^[a-zA-Z0-9_-]+$', v):
                raise ValueError('Username can only contain letters, numbers, underscores, and hyphens')

            # Prevent reserved usernames
            reserved_usernames = {
                'admin', 'administrator', 'root', 'api', 'www', 'mail', 'ftp',
                'test', 'guest', 'user', 'support', 'help', 'info', 'sales',
                'security', 'system', 'null', 'undefined', 'true', 'false'
            }

            if v.lower() in reserved_usernames:
                raise ValueError('Username is reserved, please choose another')

            # Prevent usernames that look like email addresses
            if '@' in v or '.' in v:
                raise ValueError('Username cannot contain @ or . characters')

        return v

    @field_validator('first_name', 'last_name')
    @classmethod
    def validate_names(cls, v):
        if v is not None:
            v = sanitize_text(v)
            # Names should only contain letters, spaces, hyphens, apostrophes
            if not re.match(r"^[a-zA-Z\s\-']+$", v):
                raise ValueError('Name can only contain letters, spaces, hyphens, and apostrophes')
        return v

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        # Convert email to lowercase and validate domain
        email = v.lower()

        # Basic domain validation
        domain = email.split('@')[1]
        if len(domain) < 3 or '.' not in domain:
            raise ValueError('Invalid email domain')

        return email

    @model_validator(mode='after')
    def validate_registration_data(self):
        """Cross-field validation"""
        email = self.email
        username = self.username

        # Ensure username doesn't match email prefix
        if email and username:
            email_prefix = email.split('@')[0]
            if username.lower() == email_prefix.lower():
                raise ValueError('Username should not match email prefix for security')

        return self


class UserLogin(BaseModel):
    """
    Schema for user login request with security enhancements
    """
    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., min_length=1, max_length=100, description="User's password")

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        return v.lower()

    @field_validator('password')
    @classmethod
    def validate_password_length(cls, v):
        # Don't validate strength on login, just basic checks
        if len(v) > 100:
            raise ValueError('Password too long')
        return v


class UserResponse(BaseModel):
    """
    Schema for user response (public user data) - safe for external consumption
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

    model_config = {"from_attributes": True}

    @field_validator('email')
    @classmethod
    def mask_email(cls, v):
        """Partially mask email for privacy"""
        if '@' in v:
            username, domain = v.split('@', 1)
            if len(username) > 2:
                masked_username = username[0] + '*' * (len(username) - 2) + username[-1]
                return f"{masked_username}@{domain}"
        return v


class UserProfile(BaseModel):
    """
    Schema for detailed user profile (private data) - internal use only
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

    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    """
    Schema for updating user profile with security validations
    """
    first_name: Optional[str] = Field(None, max_length=100)
    last_name: Optional[str] = Field(None, max_length=100)
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    phone: Optional[str] = Field(None, max_length=20)
    bio: Optional[str] = Field(None, max_length=1000)
    timezone: Optional[str] = Field(None, max_length=50)
    language: Optional[str] = Field(None, max_length=10)

    @field_validator('first_name', 'last_name')
    @classmethod
    def validate_names(cls, v):
        if v is not None:
            v = sanitize_text(v)
            if not re.match(r"^[a-zA-Z\s\-']+$", v):
                raise ValueError('Name can only contain letters, spaces, hyphens, and apostrophes')
        return v

    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        if v is not None:
            v = sanitize_text(v)
            if not re.match(r'^[a-zA-Z0-9_-]+$', v):
                raise ValueError('Username can only contain letters, numbers, underscores, and hyphens')

            # Check reserved usernames
            reserved_usernames = {
                'admin', 'administrator', 'root', 'api', 'www', 'mail', 'ftp',
                'test', 'guest', 'user', 'support', 'help', 'info', 'sales'
            }
            if v.lower() in reserved_usernames:
                raise ValueError('Username is reserved, please choose another')
        return v

    @field_validator('phone')
    @classmethod
    def validate_phone(cls, v):
        if v is not None:
            return validate_phone_number(v)
        return v

    @field_validator('bio')
    @classmethod
    def validate_bio(cls, v):
        if v is not None:
            v = sanitize_text(v)
            # Additional bio-specific validation
            if len(v.strip()) < 3 and len(v.strip()) > 0:
                raise ValueError('Bio must be at least 3 characters if provided')
        return v

    @field_validator('timezone')
    @classmethod
    def validate_timezone(cls, v):
        if v is not None:
            # Validate against pytz timezone list
            try:
                pytz.timezone(v)
            except pytz.exceptions.UnknownTimeZoneError:
                raise ValueError('Invalid timezone')
        return v

    @field_validator('language')
    @classmethod
    def validate_language(cls, v):
        if v is not None:
            if v not in ALLOWED_LANGUAGES:
                raise ValueError(f'Language must be one of: {", ".join(sorted(ALLOWED_LANGUAGES))}')
        return v

class GrantAccessRequest(BaseModel):
    """What platforms send when granting access"""
    user_id: int
    platform_id: str
    platform_api_key: str

class RevokeAccessRequest(BaseModel):
    """What platforms send when revoking access"""
    user_id: int
    platform_id: str
    platform_api_key: str

class PasswordChange(BaseModel):
    """
    Schema for password change request with enhanced security
    """
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., description="New password")

    @field_validator('new_password')
    @classmethod
    def validate_new_password(cls, v):
        return validate_password_strength(v)

    @model_validator(mode='after')
    def validate_password_change(self):
        """Ensure new password is different from current"""
        current = self.current_password
        new = self.new_password

        if current and new and current == new:
            raise ValueError('New password must be different from current password')

        return self


class PasswordReset(BaseModel):
    """
    Schema for password reset request with rate limiting consideration
    """
    email: EmailStr = Field(..., description="Email address for password reset")

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        return v.lower()


class PasswordResetConfirm(BaseModel):
    """
    Schema for password reset confirmation with security validations
    """
    token: str = Field(..., min_length=10, max_length=500, description="Password reset token")
    new_password: str = Field(..., description="New password")

    @field_validator('token')
    @classmethod
    def validate_token(cls, v):
        # Basic token format validation
        v = v.strip()
        if not re.match(r'^[A-Za-z0-9+/=._-]+$', v):
            raise ValueError('Invalid token format')
        return v

    @field_validator('new_password')
    @classmethod
    def validate_new_password(cls, v):
        return validate_password_strength(v)


class ForgotUsername(BaseModel):
    """
    Schema for forgot username request with security enhancements
    """
    email: EmailStr = Field(..., description="Email address to send username to")

    @field_validator('email')
    @classmethod
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
    Schema for simple message responses with security context
    """
    message: str
    success: bool = True
    timestamp: Optional[datetime] = Field(default_factory=lambda: datetime.utcnow())
    expires_in: Optional[int] = None
    return_url: Optional[str] = None

    @field_validator('message')
    @classmethod
    def validate_message(cls, v):
        # Sanitize response messages too
        return sanitize_text(v)


class SecurityContext(BaseModel):
    """
    Schema for security context in requests (internal use)
    """
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None
    session_id: Optional[str] = None

    @field_validator('ip_address')
    @classmethod
    def validate_ip(cls, v):
        if v is not None:
            # Basic IP validation
            if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', v):
                raise ValueError('Invalid IP address format')
        return v


# Example usage and testing
if __name__ == "__main__":
    # Test enhanced security validations

    # Test strong password
    try:
        user_data = {
            "email": "test@example.com",
            "password": "SecurePass123!",
            "first_name": "John",
            "last_name": "Doe"
        }
        user_register = UserRegister(**user_data)
        print("✅ Strong password accepted")
    except Exception as e:
        print(f"❌ Strong password error: {e}")

    # Test weak password
    try:
        weak_user = UserRegister(
            email="test@example.com",
            password="password",
            first_name="John"
        )
        print("❌ Weak password was accepted (should not happen)")
    except Exception as e:
        print(f"✅ Weak password rejected: {e}")

    # Test XSS in bio
    try:
        update_data = UserUpdate(bio="<script>alert('xss')</script>")
        print("❌ XSS was accepted (should not happen)")
    except Exception as e:
        print(f"✅ XSS rejected: {e}")

    print("Security validation tests completed!")