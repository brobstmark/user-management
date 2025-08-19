"""
Authentication Dependencies with httpOnly Cookie Support
Enhanced security with cookie-based JWT authentication
"""
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from jose import JWTError

from backend.config.database import get_db
from backend.core.security import verify_token
from backend.crud.user import get_user_by_email
from backend.models.user import User
from backend.utils.logging import get_security_logger, log_security_event

# Security logger
security_logger = get_security_logger()

# Optional: Keep HTTPBearer for API documentation, but we'll primarily use cookies
security = HTTPBearer(auto_error=False)


def get_token_from_cookie(request: Request) -> str:
    """
    Extract JWT token from httpOnly cookie
    
    Args:
        request: FastAPI request object
        
    Returns:
        JWT token string
        
    Raises:
        HTTPException: If token is missing or invalid
    """
    token = request.cookies.get("access_token")
    
    if not token:
        # Log missing token attempt
        client_ip = request.client.host if request.client else "unknown"
        security_logger.warning(
            "Authentication attempted without token",
            extra={
                'client_ip': client_ip,
                'path': request.url.path,
                'method': request.method,
                'user_agent': request.headers.get('user-agent', 'unknown')
            }
        )
        
        log_security_event(
            event_type="authentication",
            action="missing_token",
            result="failure",
            client_ip=client_ip,
            path=str(request.url.path)
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return token


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> User:
    """
    Get current authenticated user from httpOnly cookie or Authorization header
    
    Supports both cookie-based authentication (primary) and Authorization header (fallback)
    
    Args:
        request: FastAPI request object
        db: Database session
        credentials: Optional Authorization header credentials
        
    Returns:
        Authenticated User object
        
    Raises:
        HTTPException: If authentication fails
    """
    client_ip = request.client.host if request.client else "unknown"
    token = None
    auth_method = None
    
    # Try to get token from cookie first (preferred method)
    try:
        token = request.cookies.get("access_token")
        if token:
            auth_method = "cookie"
    except Exception as e:
        security_logger.warning(
            "Failed to read authentication cookie",
            extra={
                'client_ip': client_ip,
                'error_type': type(e).__name__
            }
        )
    
    # Fallback to Authorization header if no cookie
    if not token and credentials:
        token = credentials.credentials
        auth_method = "header"
    
    # No authentication found
    if not token:
        security_logger.warning(
            "No authentication credentials provided",
            extra={
                'client_ip': client_ip,
                'path': request.url.path,
                'method': request.method
            }
        )
        
        log_security_event(
            event_type="authentication",
            action="no_credentials",
            result="failure",
            client_ip=client_ip
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verify the token
    try:
        payload = verify_token(token)
        email: str = payload.get("sub")
        user_id: int = payload.get("user_id")
        
        if email is None or user_id is None:
            security_logger.warning(
                "Invalid token payload",
                extra={
                    'client_ip': client_ip,
                    'auth_method': auth_method,
                    'has_email': email is not None,
                    'has_user_id': user_id is not None
                }
            )
            
            log_security_event(
                event_type="authentication",
                action="invalid_token_payload",
                result="failure",
                client_ip=client_ip,
                auth_method=auth_method
            )
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
    except JWTError as e:
        security_logger.warning(
            "JWT token verification failed",
            extra={
                'client_ip': client_ip,
                'auth_method': auth_method,
                'error_type': type(e).__name__,
                'error_message': str(e)
            }
        )
        
        log_security_event(
            event_type="authentication",
            action="jwt_verification_failed",
            result="failure",
            client_ip=client_ip,
            auth_method=auth_method,
            error_type=type(e).__name__
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Get user from database
    user = get_user_by_email(db, email=email)
    if user is None:
        security_logger.warning(
            "User not found for valid token",
            extra={
                'client_ip': client_ip,
                'auth_method': auth_method,
                'email': email,  # Will be redacted
                'user_id': user_id
            }
        )
        
        log_security_event(
            event_type="authentication",
            action="user_not_found",
            result="failure",
            client_ip=client_ip,
            user_id=user_id,
            email=email  # Will be redacted
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verify user ID matches token
    if user.id != user_id:
        security_logger.warning(
            "User ID mismatch in token",
            extra={
                'client_ip': client_ip,
                'auth_method': auth_method,
                'token_user_id': user_id,
                'db_user_id': user.id,
                'email': email  # Will be redacted
            }
        )
        
        log_security_event(
            event_type="authentication",
            action="user_id_mismatch",
            result="failure",
            client_ip=client_ip,
            token_user_id=user_id,
            db_user_id=user.id
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token mismatch",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Log successful authentication
    security_logger.debug(
        "User authentication successful",
        extra={
            'user_id': user.id,
            'email': user.email,  # Will be redacted
            'auth_method': auth_method,
            'client_ip': client_ip
        }
    )
    
    return user


def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """
    Get current authenticated and active user
    
    Args:
        current_user: User from get_current_user dependency
        
    Returns:
        Active User object
        
    Raises:
        HTTPException: If user is inactive
    """
    if not current_user.is_active:
        security_logger.warning(
            "Inactive user attempted access",
            extra={
                'user_id': current_user.id,
                'email': current_user.email,  # Will be redacted
                'is_active': current_user.is_active
            }
        )
        
        log_security_event(
            event_type="authentication",
            action="inactive_user_access",
            result="failure",
            user_id=current_user.id
        )
        
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    
    return current_user


def get_current_verified_user(current_user: User = Depends(get_current_active_user)) -> User:
    """
    Get current authenticated, active, and verified user
    
    Args:
        current_user: User from get_current_active_user dependency
        
    Returns:
        Verified User object
        
    Raises:
        HTTPException: If user is not verified
    """
    if not current_user.is_verified:
        security_logger.warning(
            "Unverified user attempted verified-only access",
            extra={
                'user_id': current_user.id,
                'email': current_user.email,  # Will be redacted
                'is_verified': current_user.is_verified
            }
        )
        
        log_security_event(
            event_type="authorization",
            action="unverified_user_access",
            result="failure",
            user_id=current_user.id
        )
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email verification required"
        )
    
    return current_user


# Optional: Administrative user dependency
def get_current_superuser(current_user: User = Depends(get_current_active_user)) -> User:
    """
    Get current authenticated superuser
    
    Args:
        current_user: User from get_current_active_user dependency
        
    Returns:
        Superuser User object
        
    Raises:
        HTTPException: If user is not a superuser
    """
    if not current_user.is_superuser:
        security_logger.warning(
            "Non-superuser attempted admin access",
            extra={
                'user_id': current_user.id,
                'email': current_user.email,  # Will be redacted
                'is_superuser': current_user.is_superuser
            }
        )
        
        log_security_event(
            event_type="authorization",
            action="non_admin_access_attempt",
            result="failure",
            user_id=current_user.id
        )
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superuser access required"
        )
    
    return current_user