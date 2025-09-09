"""
Authentication Endpoints with Email Verification
Enhanced with Secure Logging and Audit Trail
"""
from datetime import timedelta, datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Request, Header
from sqlalchemy.orm import Session
from typing import Optional
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
from backend.services.email_service import send_password_reset_email, send_username_recovery_email, \
    send_password_changed_notification
from backend.core.middleware import generate_csrf_token
from fastapi.responses import JSONResponse
from fastapi import Response
from fastapi.responses import JSONResponse
from urllib.parse import urlparse
from backend.crud.platform import has_platform_access, grant_platform_access, get_platform, revoke_platform_access
from backend.schemas.user import GrantAccessRequest, RevokeAccessRequest
# 🔥 Import secure logging system
from backend.utils.logging import (
    get_auth_logger,
    get_security_logger,
    log_security_event,
    log_audit_event
)
from backend.crud.platform import create_platform, get_user_platforms
from pydantic import BaseModel
router = APIRouter()

# Initialize auth logger
logger = get_auth_logger()


class PlatformCreateRequest(BaseModel):
    name: str
    domain: str
    description: str
    return_url: str

class PlatformResponse(BaseModel):
    id: int
    name: str
    slug: str
    domain: str
    description: str = None
    return_url: str = None
    api_key_prefix: str
    is_active: bool
    is_verified: bool
    created_at: str

class PlatformCreateResponse(BaseModel):
    success: bool
    platform: PlatformResponse
    api_key: str  # Raw API key (only returned once)
    message: str

def validate_return_url(return_url: str) -> bool:
    """
    Validate return URL to prevent open redirect attacks

    Args:
        return_url: URL to validate

    Returns:
        True if URL is allowed, False otherwise
    """
    if not return_url:
        return False

    try:
        parsed = urlparse(return_url)

        # Allowed domains for your microservice clients
        allowed_domains = [
            "localhost:3000",  # Game platform
            "localhost:4000",  # Future platform
            "localhost:8000",  # Your auth service itself
            "127.0.0.1:3000",
            "127.0.0.1:4000",
            "127.0.0.1:8000"
        ]

        # In production, add your real domains:
        if settings.ENVIRONMENT == "production":
            allowed_domains.extend([
                "yourgame.com",
                "app.yourdomain.com",
                # etc.
            ])

        # Check if domain is in allowed list
        domain_with_port = f"{parsed.hostname}:{parsed.port}" if parsed.port else parsed.hostname

        return any(
            domain_with_port == allowed or
            domain_with_port.endswith(f".{allowed}")
            for allowed in allowed_domains
        )

    except Exception:
        return False


def verify_platform_api_key(db: Session, platform_id: str, provided_key: str) -> bool:
    """Check if platform API key is valid"""
    from backend.crud.platform import get_platform

    platform = get_platform(db, platform_id)
    if not platform:
        return False

    # Hash the provided key and compare
    import hashlib
    provided_hash = hashlib.sha256(provided_key.encode()).hexdigest()
    return provided_hash == platform.api_key


@router.post("/create-platform", response_model=PlatformCreateResponse)
async def create_platform_endpoint(
        platform_data: PlatformCreateRequest,
        request: Request,
        current_user: User = Depends(get_current_active_user),
        db: Session = Depends(get_db)
):
    """
    Create a new platform for the authenticated user

    Requires authentication. Returns the platform details and API key.
    The API key is only shown once - save it securely.
    """
    client_ip = request.client.host if request.client else "unknown"

    logger.info("Platform creation requested", extra={
        'action': 'create_platform',
        'user_id': current_user.id,
        'platform_name': platform_data.name,
        'domain': platform_data.domain,
        'ip_address': client_ip
    })

    # Create the platform
    result = create_platform(
        db=db,
        user_id=current_user.id,
        name=platform_data.name,
        domain=platform_data.domain,
        description=platform_data.description,
        return_url=platform_data.return_url
    )

    if not result["success"]:
        logger.warning("Platform creation failed", extra={
            'action': 'create_platform',
            'user_id': current_user.id,
            'errors': result["errors"],
            'ip_address': client_ip
        })

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": "Platform creation failed",
                "errors": result["errors"]
            }
        )

    platform = result["platform"]
    api_key = result["api_key"]

    # Log successful platform creation
    logger.info("Platform created successfully", extra={
        'action': 'create_platform',
        'user_id': current_user.id,
        'platform_id': platform.id,
        'platform_slug': platform.slug,
        'domain': platform.domain,
        'ip_address': client_ip
    })

    log_audit_event(
        action="create_platform",
        resource="platform",
        result="success",
        user_id=current_user.id,
        platform_id=platform.id,
        ip_address=client_ip
    )

    # Return platform data and API key
    return PlatformCreateResponse(
        success=True,
        platform=PlatformResponse(
            id=platform.id,
            name=platform.name,
            slug=platform.slug,
            domain=platform.domain,
            description=platform.description,
            return_url=platform.return_url,
            api_key_prefix=platform.api_key_prefix,
            is_active=platform.is_active,
            is_verified=platform.is_verified,
            created_at=platform.created_at.isoformat()
        ),
        api_key=api_key,
        message="Platform created successfully! Save your API key securely - it won't be shown again."
    )


@router.get("/platforms", response_model=list[PlatformResponse])
async def get_user_platforms_endpoint(
        request: Request,
        current_user: User = Depends(get_current_active_user),
        db: Session = Depends(get_db)
):
    """
    Get all platforms owned by the authenticated user
    """
    client_ip = request.client.host if request.client else "unknown"

    logger.debug("User platforms requested", extra={
        'action': 'get_user_platforms',
        'user_id': current_user.id,
        'ip_address': client_ip
    })

    platforms = get_user_platforms(db, current_user.id)

    return [
        PlatformResponse(
            id=platform.id,
            name=platform.name,
            slug=platform.slug,
            domain=platform.domain,
            description=platform.description,
            return_url=platform.return_url,
            api_key_prefix=platform.api_key_prefix,
            is_active=platform.is_active,
            is_verified=platform.is_verified,
            created_at=platform.created_at.isoformat()
        )
        for platform in platforms
    ]

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    user_data: UserRegister,
    request: Request,
    return_url: Optional[str] = None,
    platform_id: Optional[str] = None,  # ADD THIS LINE
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
    # Get client IP for security logging
    client_ip = request.client.host if request.client else "unknown"

    logger.info("User registration attempt", extra={
        'action': 'register',
        'email': user_data.email,  # Will be redacted
        'ip_address': client_ip,
        'username': user_data.username
    })

    # Create the user
    result = create_user(db, user_data)

    if not result["success"]:
        logger.warning("User registration failed - validation errors", extra={
            'action': 'register',
            'email': user_data.email,  # Will be redacted
            'errors': result["errors"],
            'ip_address': client_ip
        })

        log_security_event(
            event_type="registration",
            action="register_user",
            result="validation_failure",
            ip_address=client_ip,
            email=user_data.email  # Will be redacted
        )



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

    logger.debug("Generated verification token for new user", extra={
        'action': 'generate_verification_token',
        'user_id': user.id,
        'email': user.email  # Will be redacted
    })

    # Send verification email
    from backend.services.email_service import send_verification_email
    user_name = user.first_name or user.email.split('@')[0]

    try:
        email_sent = await send_verification_email(
            user_email=user.email,
            user_name=user_name,
            verification_token=verification_token
        )

        if email_sent:
            logger.info("Verification email sent successfully", extra={
                'action': 'send_verification_email',
                'user_id': user.id,
                'email': user.email  # Will be redacted
            })
        else:
            logger.warning("Verification email sending failed", extra={
                'action': 'send_verification_email',
                'user_id': user.id,
                'email': user.email  # Will be redacted
            })

    except Exception as e:
        logger.error("Exception occurred while sending verification email", extra={
            'action': 'send_verification_email',
            'user_id': user.id,
            'email': user.email,  # Will be redacted
            'error_type': type(e).__name__,
            'error_message': str(e)
        })

    # Log successful registration
    log_security_event(
        event_type="registration",
        action="register_user",
        result="success",
        user_id=user.id,
        ip_address=client_ip,
        email=user.email  # Will be redacted
    )

    log_audit_event(
        action="create_user_account",
        resource="user_account",
        result="success",
        user_id=user.id,
        ip_address=client_ip
    )

    logger.info("User registration completed successfully", extra={
        'action': 'register',
        'user_id': user.id,
        'email': user.email,  # Will be redacted
        'ip_address': client_ip
    })

    return user


@router.post("/login", response_model=MessageResponse)  # Changed from TokenResponse
async def login_user(
    login_data: UserLogin,
    request: Request,
    response: Response,
    return_url: Optional[str] = None,
    platform_id: Optional[str] = None,
    db: Session = Depends(get_db)
):

    """
    User login endpoint with httpOnly cookie authentication

    - **email**: User's email address
    - **password**: User's password

    Returns success message and sets httpOnly authentication cookie
    """
    # Get client IP for security logging
    client_ip = request.client.host if request.client else "unknown"

    # Validate return URL if provided
    if return_url and not validate_return_url(return_url):
        logger.warning("Login attempted with invalid return URL", extra={
            'action': 'login',
            'email': login_data.email,
            'ip_address': client_ip,
            'invalid_return_url': return_url
        })

        log_security_event(
            event_type="authentication",
            action="invalid_return_url",
            result="blocked",
            ip_address=client_ip,
            return_url=return_url
        )

        logger.warning(f"Invalid return URL attempted: {return_url}")

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid return URL"
        )

    logger.info("Login attempt", extra={
        'action': 'login',
        'email': login_data.email,  # Will be redacted
        'ip_address': client_ip
    })

    # Get user by email
    user = get_user_by_email(db, login_data.email)

    if not user:
        logger.warning("Login failed - user not found", extra={
            'action': 'login',
            'email': login_data.email,  # Will be redacted
            'ip_address': client_ip,
            'failure_reason': 'user_not_found'
        })

        log_security_event(
            event_type="authentication",
            action="login",
            result="failure",
            failure_reason="invalid_credentials",
            ip_address=client_ip,
            email=login_data.email  # Will be redacted
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )

    # Verify password
    if not verify_password(login_data.password, user.hashed_password):
        logger.warning("Login failed - invalid password", extra={
            'action': 'login',
            'user_id': user.id,
            'email': user.email,  # Will be redacted
            'ip_address': client_ip,
            'failure_reason': 'invalid_password'
        })

        log_security_event(
            event_type="authentication",
            action="login",
            result="failure",
            failure_reason="invalid_credentials",
            user_id=user.id,
            ip_address=client_ip,
            email=user.email  # Will be redacted
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )

    # Check if user is active
    if not user.is_active:
        logger.warning("Login failed - account deactivated", extra={
            'action': 'login',
            'user_id': user.id,
            'email': user.email,  # Will be redacted
            'ip_address': client_ip,
            'failure_reason': 'account_deactivated'
        })

        log_security_event(
            event_type="authentication",
            action="login",
            result="failure",
            failure_reason="account_deactivated",
            user_id=user.id,
            ip_address=client_ip
        )

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

    # Set httpOnly authentication cookie
    response.set_cookie(
        key="access_token",
        value=access_token,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # Convert to seconds
        httponly=True,  # Critical: prevents JavaScript access
        secure=settings.ENVIRONMENT == "production",  # HTTPS only in production
        samesite="strict"  # CSRF protection
    )

    # Log successful login
    logger.info("Login successful", extra={
        'action': 'login',
        'user_id': user.id,
        'email': user.email,  # Will be redacted
        'ip_address': client_ip,
        'token_expires_in': settings.ACCESS_TOKEN_EXPIRE_MINUTES
    })

    log_security_event(
        event_type="authentication",
        action="login",
        result="success",
        user_id=user.id,
        ip_address=client_ip,
        session_duration=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )

    log_audit_event(
        action="user_login",
        resource="user_session",
        result="success",
        user_id=user.id,
        ip_address=client_ip
    )

    # Prepare response data
    response_data = {
        "message": "Login successful",
        "success": True,
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }

    # Add return URL if provided
    if return_url:
        response_data["return_url"] = return_url

    return response_data


@router.post("/logout", response_model=MessageResponse)
async def logout_user(
        request: Request,
        response: Response,
        current_user: User = Depends(get_current_active_user)
):
    """
    User logout endpoint - clears authentication cookie
    """
    client_ip = request.client.host if request.client else "unknown"

    logger.info("User logout", extra={
        'action': 'logout',
        'user_id': current_user.id,
        'email': current_user.email,  # Will be redacted
        'ip_address': client_ip
    })

    # Clear authentication cookie
    response.delete_cookie(
        key="access_token",
        httponly=True,
        secure=settings.ENVIRONMENT == "production",
        samesite="strict"
    )

    log_audit_event(
        action="user_logout",
        resource="user_session",
        result="success",
        user_id=current_user.id,
        ip_address=client_ip
    )

    return {
        "message": "Successfully logged out",
        "success": True
    }



@router.get("/auth-status", response_model=dict)
async def get_auth_status(
        request: Request,
        current_user: User = Depends(get_current_active_user)
):
    """
    Check current authentication status

    Requires: Valid authentication cookie
    """
    logger.debug("Authentication status checked", extra={
        'action': 'check_auth_status',
        'user_id': current_user.id,
        'is_verified': current_user.is_verified
    })

    return {
        "authenticated": True,
        "user": {
            "id": current_user.id,
            "email": current_user.email,
            "first_name": current_user.first_name,
            "last_name": current_user.last_name,
            "is_verified": current_user.is_verified,
            "is_active": current_user.is_active
        }
    }

@router.get("/csrf-token", response_model=dict)
async def get_csrf_token(request: Request):
    """Generate and return CSRF token"""
    csrf_token = generate_csrf_token()

    response = JSONResponse({
        "csrf_token": csrf_token,
        "message": "CSRF token generated"
    })

    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        max_age=7200,  # 2 hours
        httponly=True,
        secure=settings.ENVIRONMENT == "production",
        samesite="strict"
    )

    return response

@router.post("/send-verification", response_model=MessageResponse)
async def send_verification_email_endpoint(
        request: Request,
        current_user: User = Depends(get_current_active_user),
        db: Session = Depends(get_db)
):
    """
    Send email verification to current user

    Requires: Valid JWT token
    """
    client_ip = request.client.host if request.client else "unknown"

    logger.info("Verification email resend requested", extra={
        'action': 'resend_verification',
        'user_id': current_user.id,
        'email': current_user.email,  # Will be redacted
        'ip_address': client_ip
    })

    # Check if already verified
    if current_user.is_verified:
        logger.info("Verification email requested but already verified", extra={
            'action': 'resend_verification',
            'user_id': current_user.id,
            'email': current_user.email  # Will be redacted
        })

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

    logger.debug("Generated new verification token", extra={
        'action': 'generate_verification_token',
        'user_id': current_user.id
    })

    # Send verification email
    from backend.services.email_service import send_verification_email
    user_name = current_user.first_name or current_user.email.split('@')[0]

    email_sent = await send_verification_email(
        user_email=current_user.email,
        user_name=user_name,
        verification_token=verification_token
    )

    if not email_sent:
        logger.error("Failed to resend verification email", extra={
            'action': 'resend_verification',
            'user_id': current_user.id,
            'email': current_user.email  # Will be redacted
        })

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send verification email"
        )

    logger.info("Verification email resent successfully", extra={
        'action': 'resend_verification',
        'user_id': current_user.id,
        'email': current_user.email  # Will be redacted
    })

    return {
        "message": "Verification email sent successfully",
        "success": True
    }


@router.get("/verify-email", response_model=MessageResponse)
async def verify_email_endpoint(
        token: str,
        request: Request,
        db: Session = Depends(get_db)
):
    """
    Verify user's email address using verification token

    Args:
        token: Email verification token (from email link)
    """
    client_ip = request.client.host if request.client else "unknown"

    logger.info("Email verification attempt", extra={
        'action': 'verify_email',
        'ip_address': client_ip
    })

    # Verify the token
    email = verify_email_verification_token(token)

    if not email:
        logger.warning("Email verification failed - invalid token", extra={
            'action': 'verify_email',
            'ip_address': client_ip,
            'failure_reason': 'invalid_token'
        })

        log_security_event(
            event_type="email_verification",
            action="verify_email",
            result="failure",
            failure_reason="invalid_token",
            ip_address=client_ip
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token"
        )

    # Find user by email
    user = get_user_by_email(db, email)
    if not user:
        logger.warning("Email verification failed - user not found", extra={
            'action': 'verify_email',
            'email': email,  # Will be redacted
            'ip_address': client_ip,
            'failure_reason': 'user_not_found'
        })

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Check if token matches the one in database
    if user.email_verification_token != token:
        logger.warning("Email verification failed - token mismatch", extra={
            'action': 'verify_email',
            'user_id': user.id,
            'email': user.email,  # Will be redacted
            'ip_address': client_ip,
            'failure_reason': 'token_mismatch'
        })

        log_security_event(
            event_type="email_verification",
            action="verify_email",
            result="failure",
            failure_reason="token_mismatch",
            user_id=user.id,
            ip_address=client_ip
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification token"
        )

    # Check if already verified
    if user.is_verified:
        logger.info("Email verification - already verified", extra={
            'action': 'verify_email',
            'user_id': user.id,
            'email': user.email  # Will be redacted
        })

        return {
            "message": "Email is already verified",
            "success": True
        }

    # Mark email as verified
    from backend.crud.user import verify_user_email
    success = verify_user_email(db, user.id)

    if not success:
        logger.error("Email verification failed - database error", extra={
            'action': 'verify_email',
            'user_id': user.id,
            'email': user.email  # Will be redacted
        })

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify email"
        )

    # Log successful verification
    logger.info("Email verification successful", extra={
        'action': 'verify_email',
        'user_id': user.id,
        'email': user.email,  # Will be redacted
        'ip_address': client_ip
    })

    log_security_event(
        event_type="email_verification",
        action="verify_email",
        result="success",
        user_id=user.id,
        ip_address=client_ip
    )

    log_audit_event(
        action="verify_user_email",
        resource="user_account",
        result="success",
        user_id=user.id,
        ip_address=client_ip
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
    logger.debug("Verification status checked", extra={
        'action': 'check_verification_status',
        'user_id': current_user.id,
        'is_verified': current_user.is_verified
    })

    return {
        "email": current_user.email,
        "is_verified": current_user.is_verified,
        "verification_sent_at": current_user.email_verification_sent_at.isoformat() if current_user.email_verification_sent_at else None
    }


@router.post("/forgot-password", response_model=MessageResponse)
async def forgot_password(
        request: PasswordReset,
        http_request: Request,
        db: Session = Depends(get_db)
):
    """
    Request password reset - sends email with reset link

    Args:
        request: Password reset request with email

    Returns:
        Success message (always returns success to prevent email enumeration)
    """
    client_ip = http_request.client.host if http_request.client else "unknown"

    logger.info("Password reset requested", extra={
        'action': 'forgot_password',
        'email': request.email,  # Will be redacted
        'ip_address': client_ip
    })

    # Always return success message to prevent email enumeration attacks
    success_message = "If the email address exists, password reset instructions have been sent"

    # Find user by email
    user = get_user_by_email(db, request.email)

    if not user:
        logger.info("Password reset requested for non-existent email", extra={
            'action': 'forgot_password',
            'email': request.email,  # Will be redacted
            'ip_address': client_ip,
            'result': 'email_not_found'
        })

        log_security_event(
            event_type="password_reset",
            action="forgot_password",
            result="email_not_found",
            ip_address=client_ip,
            email=request.email  # Will be redacted
        )

        return {
            "message": success_message,
            "success": True
        }

    if not user.is_active:
        logger.info("Password reset requested for inactive account", extra={
            'action': 'forgot_password',
            'user_id': user.id,
            'email': user.email,  # Will be redacted
            'ip_address': client_ip,
            'result': 'account_inactive'
        })

        log_security_event(
            event_type="password_reset",
            action="forgot_password",
            result="account_inactive",
            user_id=user.id,
            ip_address=client_ip
        )

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
            logger.warning("Failed to save password reset token", extra={
                'action': 'forgot_password',
                'user_id': user.id,
                'email': user.email  # Will be redacted
            })

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
            logger.info("Password reset email sent successfully", extra={
                'action': 'forgot_password',
                'user_id': user.id,
                'email': user.email,  # Will be redacted
                'ip_address': client_ip
            })

            log_security_event(
                event_type="password_reset",
                action="send_reset_email",
                result="success",
                user_id=user.id,
                ip_address=client_ip
            )
        else:
            logger.warning("Failed to send password reset email", extra={
                'action': 'forgot_password',
                'user_id': user.id,
                'email': user.email  # Will be redacted
            })

    except Exception as e:
        logger.error("Error in forgot password process", extra={
            'action': 'forgot_password',
            'email': request.email,  # Will be redacted
            'error_type': type(e).__name__,
            'error_message': str(e),
            'ip_address': client_ip
        })

        log_security_event(
            event_type="password_reset",
            action="forgot_password",
            result="error",
            error_type=type(e).__name__,
            ip_address=client_ip
        )

    return {
        "message": success_message,
        "success": True
    }


@router.post("/reset-password", response_model=MessageResponse)
async def reset_password(
        request: PasswordResetConfirm,
        http_request: Request,
        db: Session = Depends(get_db)
):
    """
    Reset password using reset token

    Args:
        request: Password reset confirmation with token and new password

    Returns:
        Success/error message
    """
    client_ip = http_request.client.host if http_request.client else "unknown"

    logger.info("Password reset confirmation attempt", extra={
        'action': 'reset_password',
        'ip_address': client_ip
    })

    # Verify the reset token
    email = verify_password_reset_token(request.token)

    if not email:
        logger.warning("Password reset failed - invalid token", extra={
            'action': 'reset_password',
            'ip_address': client_ip,
            'failure_reason': 'invalid_token'
        })

        log_security_event(
            event_type="password_reset",
            action="reset_password",
            result="failure",
            failure_reason="invalid_token",
            ip_address=client_ip
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token"
        )

    # Reset the password
    result = reset_password_with_token(db, request.token, request.new_password)

    if not result["success"]:
        user = get_user_by_email(db, email)
        user_id = user.id if user else None

        logger.warning("Password reset failed - validation errors", extra={
            'action': 'reset_password',
            'user_id': user_id,
            'email': email,  # Will be redacted
            'errors': result["errors"],
            'ip_address': client_ip
        })

        log_security_event(
            event_type="password_reset",
            action="reset_password",
            result="validation_failure",
            user_id=user_id,
            ip_address=client_ip
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": "Password reset failed",
                "errors": result["errors"]
            }
        )

    # Get user for logging and notification
    user = get_user_by_email(db, email)

    # Log successful password reset
    logger.info("Password reset completed successfully", extra={
        'action': 'reset_password',
        'user_id': user.id if user else None,
        'email': email,  # Will be redacted
        'ip_address': client_ip
    })

    log_security_event(
        event_type="password_reset",
        action="reset_password",
        result="success",
        user_id=user.id if user else None,
        ip_address=client_ip
    )

    log_audit_event(
        action="reset_user_password",
        resource="user_account",
        result="success",
        user_id=user.id if user else None,
        ip_address=client_ip
    )

    # Send confirmation email
    try:
        if user:
            user_name = user.first_name or user.email.split('@')[0]
            await send_password_changed_notification(user.email, user_name)
    except Exception as e:
        logger.warning("Failed to send password changed notification", extra={
            'action': 'send_password_changed_notification',
            'user_id': user.id if user else None,
            'error_type': type(e).__name__,
            'error_message': str(e)
        })

    return {
        "message": "Password has been reset successfully. You can now log in with your new password.",
        "success": True
    }


@router.post("/forgot-username", response_model=MessageResponse)
async def forgot_username(
        request: ForgotUsername,
        http_request: Request,
        db: Session = Depends(get_db)
):
    """
    Send username to user's email address

    Args:
        request: Forgot username request with email

    Returns:
        Success message (always returns success to prevent email enumeration)
    """
    client_ip = http_request.client.host if http_request.client else "unknown"

    logger.info("Username recovery requested", extra={
        'action': 'forgot_username',
        'email': request.email,  # Will be redacted
        'ip_address': client_ip
    })

    # Always return success message to prevent email enumeration attacks
    success_message = "If the email address exists, username recovery instructions have been sent"

    # Find user by email
    user = get_user_by_email(db, request.email)

    if not user:
        logger.info("Username recovery requested for non-existent email", extra={
            'action': 'forgot_username',
            'email': request.email,  # Will be redacted
            'ip_address': client_ip,
            'result': 'email_not_found'
        })

        log_security_event(
            event_type="username_recovery",
            action="forgot_username",
            result="email_not_found",
            ip_address=client_ip,
            email=request.email  # Will be redacted
        )

        return {
            "message": success_message,
            "success": True
        }

    if not user.is_active:
        logger.info("Username recovery requested for inactive account", extra={
            'action': 'forgot_username',
            'user_id': user.id,
            'email': user.email,  # Will be redacted
            'ip_address': client_ip,
            'result': 'account_inactive'
        })

        log_security_event(
            event_type="username_recovery",
            action="forgot_username",
            result="account_inactive",
            user_id=user.id,
            ip_address=client_ip
        )

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
            logger.info("Username recovery email sent successfully", extra={
                'action': 'forgot_username',
                'user_id': user.id,
                'email': user.email,  # Will be redacted
                'ip_address': client_ip
            })

            log_security_event(
                event_type="username_recovery",
                action="send_username_email",
                result="success",
                user_id=user.id,
                ip_address=client_ip
            )
        else:
            logger.warning("Failed to send username recovery email", extra={
                'action': 'forgot_username',
                'user_id': user.id,
                'email': user.email  # Will be redacted
            })

    except Exception as e:
        logger.error("Error in username recovery process", extra={
            'action': 'forgot_username',
            'email': request.email,  # Will be redacted
            'error_type': type(e).__name__,
            'error_message': str(e),
            'ip_address': client_ip
        })

        log_security_event(
            event_type="username_recovery",
            action="forgot_username",
            result="error",
            error_type=type(e).__name__,
            ip_address=client_ip
        )

    return {
        "message": success_message,
        "success": True
    }


@router.get("/validate", response_model=dict)
async def validate_external_session(
    request: Request,
    platform_id: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Check if someone is logged in (for external services)
    """
    client_ip = request.client.host if request.client else "unknown"

    try:
        # current_user is already provided by the dependency
        logger.info("External session validation successful", extra={
            'action': 'validate_external_session',
            'user_id': current_user.id,
            'ip_address': client_ip
        })

        # Check platform access if platform_id provided
        if platform_id:
            if not has_platform_access(db, current_user.id, platform_id):
                print(f"***************************DEBUGGY BUG: User {current_user.id} denied access to platform {platform_id}")
                return JSONResponse(
                    status_code=403,
                    content={
                        "valid": False,
                        "error": "platform_access_denied",
                        "message": "You don't have access to this platform"
                    }
                )
            print(f"********************************DEBUGGY BUG: User {current_user.id} has access to platform {platform_id}")

        return {
            "valid": True,
            "user": {
                "id": current_user.id,
                "email": current_user.email,
                "username": current_user.username,
                "first_name": current_user.first_name,
                "last_name": current_user.last_name
            }
        }

    except HTTPException:
        logger.info("External session validation failed", extra={
            'action': 'validate_external_session',
            'ip_address': client_ip,
            'failure_reason': 'invalid_session'
        })

        return JSONResponse(
            status_code=401,
            content={
                "valid": False,
                "error": "invalid_session",
                "message": "Authentication required"
            }
        )


@router.get("/check-email", response_model=dict)
async def check_email_exists(
        email: str,
        request: Request,
        db: Session = Depends(get_db)
):
    """
    Check if email exists in auth system (for platforms)
    """
    client_ip = request.client.host if request.client else "unknown"

    user = get_user_by_email(db, email.lower())

    logger.info("Email check requested", extra={
        'action': 'check_email',
        'email': email,
        'ip_address': client_ip,
        'found': user is not None
    })

    return {
        "exists": user is not None,
        "email": email
    }


@router.post("/grant-access", response_model=dict)
async def grant_platform_access_api(
        request_data: GrantAccessRequest,
        authorization: str = Header(None),
        db: Session = Depends(get_db)
):
    """Grant platform access - requires API key"""

    # Check for API key
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "API key required")

    api_key = authorization.split(" ")[1]

    # Verify API key belongs to this platform
    if not verify_platform_api_key(db, request_data.platform_id, api_key):
        raise HTTPException(403, "Invalid API key")

    success = grant_platform_access(db, request_data.user_id, request_data.platform_id)
    return {"success": success}


@router.post("/revoke-access", response_model=dict)
async def revoke_platform_access_api(
        request_data: RevokeAccessRequest,
        request: Request,
        authorization: str = Header(None),
        db: Session = Depends(get_db)
):
    """
    Revoke platform access - requires API key
    """
    client_ip = request.client.host if request.client else "unknown"

    # Check for API key
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "API key required")

    api_key = authorization.split(" ")[1]

    # Verify API key belongs to this platform
    if not verify_platform_api_key(db, request_data.platform_id, api_key):
        raise HTTPException(403, "Invalid API key")

    success = revoke_platform_access(db, request_data.user_id, request_data.platform_id)

    logger.info("Platform access revoked", extra={
        'action': 'revoke_access',
        'user_id': request_data.user_id,
        'platform_id': request_data.platform_id,
        'ip_address': client_ip,
        'success': success
    })

    return {
        "success": success,
        "message": f"Access revoked from {request_data.platform_id}" if success else "Access record not found"
    }

@router.post("/change-password", response_model=MessageResponse)
async def change_password_endpoint(
        request: PasswordChange,
        http_request: Request,
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
    client_ip = http_request.client.host if http_request.client else "unknown"

    logger.info("Password change requested", extra={
        'action': 'change_password',
        'user_id': current_user.id,
        'email': current_user.email,  # Will be redacted
        'ip_address': client_ip
    })

    # Change the password
    result = change_password(
        db,
        current_user.id,
        request.current_password,
        request.new_password
    )

    if not result["success"]:
        logger.warning("Password change failed", extra={
            'action': 'change_password',
            'user_id': current_user.id,
            'email': current_user.email,  # Will be redacted
            'errors': result["errors"],
            'ip_address': client_ip
        })

        log_security_event(
            event_type="password_change",
            action="change_password",
            result="failure",
            user_id=current_user.id,
            ip_address=client_ip,
            failure_reason="validation_failure"
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": "Password change failed",
                "errors": result["errors"]
            }
        )

    # Log successful password change
    logger.info("Password changed successfully", extra={
        'action': 'change_password',
        'user_id': current_user.id,
        'email': current_user.email,  # Will be redacted
        'ip_address': client_ip
    })

    log_security_event(
        event_type="password_change",
        action="change_password",
        result="success",
        user_id=current_user.id,
        ip_address=client_ip
    )

    log_audit_event(
        action="change_user_password",
        resource="user_account",
        result="success",
        user_id=current_user.id,
        ip_address=client_ip
    )

    # Send confirmation email
    try:
        user_name = current_user.first_name or current_user.email.split('@')[0]
        await send_password_changed_notification(current_user.email, user_name)
    except Exception as e:
        logger.warning("Failed to send password changed notification", extra={
            'action': 'send_password_changed_notification',
            'user_id': current_user.id,
            'error_type': type(e).__name__,
            'error_message': str(e)
        })

    return {
        "message": "Password has been changed successfully.",
        "success": True
    }

