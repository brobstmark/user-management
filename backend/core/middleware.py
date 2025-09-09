# Add this to your backend/core/middleware.py (create if it doesn't exist)

"""
Enterprise Security Middleware
Implements comprehensive security headers and CSRF protection
"""
import secrets
import time
from typing import Callable
from fastapi import Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from backend.config.settings import settings
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from sqlalchemy import text
from backend.config.database import get_db
import uuid
from backend.utils.logging import (
    get_api_logger,
    get_security_logger,
    log_security_event
)
# Security logger
security_logger = get_security_logger()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Comprehensive security headers middleware
    Implements CSP, HSTS, CSRF protection, and other security headers
    """

    def __init__(self, app):
        super().__init__(app)
        self.csrf_tokens = {}  # In production, use Redis or database
        self.last_cleanup = time.time()

    async def dispatch(self, request, call_next):
        # 1) CSRF at the door for state-changing API calls
        if request.method in {"POST", "PUT", "DELETE", "PATCH"} and request.url.path.startswith("/api/"):
            await self._handle_csrf_protection(request)  # note: no 'response' arg

        # 2) Only then let the request in
        response = await call_next(request)

        # 3) Add security headers, cleanups, etc.
        self._add_security_headers(response, request)
        self._cleanup_expired_tokens()
        return response

    def _add_security_headers(self, response: Response, request: Request):
        """Add comprehensive security headers"""

        # Content Security Policy - Strict but functional
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "base-uri 'self'; "
            "object-src 'none'"
        )

        if settings.ENVIRONMENT == "development":
            # Slightly relaxed CSP for development
            csp_policy = csp_policy.replace("'unsafe-inline'", "'unsafe-inline' 'unsafe-eval'")

        # Core security headers
        response.headers["Content-Security-Policy"] = csp_policy
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), "
            "payment=(), usb=(), magnetometer=(), gyroscope=()"
        )

        # HSTS for HTTPS (only add in production)
        if settings.ENVIRONMENT == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        # Cache control for sensitive pages
        if request.url.path.startswith("/api/") or "auth" in request.url.path:
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"

        # Custom security headers
        response.headers["X-Robots-Tag"] = "noindex, nofollow"
        if settings.ENVIRONMENT != "production":
            response.headers["X-Debug-Mode"] = "true"

    async def _handle_csrf_protection(self, request: Request):
        """Handle CSRF protection for state-changing requests"""


        CSRF_EXEMPT_PATHS = {
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/api/v1/auth/forgot-password",
            "/api/v1/auth/reset-password",
            "/api/v1/health",
            "/api/config",
            "/api/v1/logs/frontend",
            "/api/v1/auth/grant-access",
            "/api/v1/auth/revoke-access",
            "/api/v1/auth/check-email",
        }
        if request.url.path in CSRF_EXEMPT_PATHS:
            return
        # Get CSRF token from cookie
        csrf_token = request.cookies.get("csrf_token")

        # Get CSRF token from header
        csrf_header = request.headers.get("X-CSRF-Token")

        if not csrf_token or not csrf_header or csrf_token != csrf_header:
            security_logger.warning(
                "CSRF token validation failed",
                extra={
                    'path': request.url.path,
                    'method': request.method,
                    'client_ip': self._get_client_ip(request),
                    'has_cookie_token': bool(csrf_token),
                    'has_header_token': bool(csrf_header),
                    'tokens_match': csrf_token == csrf_header if csrf_token and csrf_header else False
                }
            )

            log_security_event(
                event_type="csrf_violation",
                action=f"{request.method} {request.url.path}",
                result="blocked",
                client_ip=self._get_client_ip(request)
            )

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF token validation failed"
            )

    def _cleanup_expired_tokens(self):
        """Clean up expired CSRF tokens periodically"""
        now = time.time()
        if now - self.last_cleanup > 3600:  # Clean up every hour
            expired_tokens = [
                token for token, timestamp in self.csrf_tokens.items()
                if now - timestamp > 7200  # 2 hours expiry
            ]
            for token in expired_tokens:
                del self.csrf_tokens[token]
            self.last_cleanup = now

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address"""
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip

        return request.client.host if request.client else "unknown"


class RateLimitingMiddleware(BaseHTTPMiddleware):
    """
    Database-based rate limiting middleware
    Protects critical endpoints from abuse
    """

    def __init__(self, app):
        super().__init__(app)
        self.security_logger = get_security_logger()

        # Rate limiting configuration
        self.rate_limits = {
            # Endpoint: (max_requests, window_minutes)
            "POST:/api/v1/auth/login": (5, 15),  # 5 attempts per 15 minutes
            "POST:/api/v1/auth/register": (3, 60),  # 3 attempts per hour
            "POST:/api/v1/auth/forgot-password": (3, 60),  # 3 attempts per hour
            "POST:/api/v1/auth/forgot-username": (3, 60),  # 3 attempts per hour
            "POST:/api/v1/auth/reset-password": (5, 60),  # 5 attempts per hour
            "POST:/api/v1/auth/verify-email": (10, 60),  # 10 attempts per hour
            "POST:/api/v1/auth/send-verification": (5, 60),  # 5 attempts per hour
        }

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Check rate limits for protected endpoints
        endpoint_key = f"{request.method}:{request.url.path}"

        if endpoint_key in self.rate_limits:
            client_ip = self._get_client_ip(request)

            # Check if rate limit is exceeded
            is_allowed, remaining, reset_time = await self._check_rate_limit(
                client_ip, endpoint_key
            )

            if not is_allowed:
                self.security_logger.warning(
                    "Rate limit exceeded",
                    extra={
                        'client_ip': client_ip,
                        'endpoint': endpoint_key,
                        'reset_time': reset_time.isoformat() if reset_time else None
                    }
                )

                log_security_event(
                    event_type="rate_limit",
                    action=endpoint_key,
                    result="blocked",
                    client_ip=client_ip
                )

                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "Rate limit exceeded",
                        "message": f"Too many requests. Try again in {remaining} minutes.",
                        "retry_after": remaining * 60  # seconds
                    },
                    headers={
                        "Retry-After": str(remaining * 60),
                        "X-RateLimit-Limit": str(self.rate_limits[endpoint_key][0]),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(int(reset_time.timestamp())) if reset_time else ""
                    }
                )

        # Process request normally
        response = await call_next(request)

        # Add rate limit headers to successful responses
        if endpoint_key in self.rate_limits:
            client_ip = self._get_client_ip(request)
            _, remaining_requests, reset_time = await self._get_rate_limit_status(client_ip, endpoint_key)

            max_requests = self.rate_limits[endpoint_key][0]
            response.headers["X-RateLimit-Limit"] = str(max_requests)
            response.headers["X-RateLimit-Remaining"] = str(max(0, max_requests - remaining_requests))
            if reset_time:
                response.headers["X-RateLimit-Reset"] = str(int(reset_time.timestamp()))

        return response

    async def _check_rate_limit(self, ip_address: str, endpoint: str) -> tuple[bool, int, datetime]:
        """
        Check if request is within rate limits

        Returns:
            (is_allowed, minutes_until_reset, reset_time)
        """
        max_requests, window_minutes = self.rate_limits[endpoint]

        # Use dependency injection to get database session
        db_gen = get_db()
        db: Session = next(db_gen)

        try:
            now = datetime.now(timezone.utc)
            window_start = now - timedelta(minutes=window_minutes)

            # Clean up expired entries first
            await self._cleanup_expired_entries(db)

            # Check current count
            result = db.execute(
                text("""
                    SELECT count, expires_at, first_request_at
                    FROM rate_limits 
                    WHERE ip_address = :ip_address 
                    AND endpoint = :endpoint 
                    AND expires_at > :now
                """),
                {
                    "ip_address": ip_address,
                    "endpoint": endpoint,
                    "now": now
                }
            ).fetchone()

            if result:
                current_count, expires_at, first_request_at = result

                if current_count >= max_requests:
                    # Rate limit exceeded
                    minutes_remaining = max(0, int((expires_at - now).total_seconds() / 60))
                    return False, minutes_remaining, expires_at

                # Increment count
                db.execute(
                    text("""
                        UPDATE rate_limits 
                        SET count = count + 1, updated_at = CURRENT_TIMESTAMP
                        WHERE ip_address = :ip_address AND endpoint = :endpoint
                    """),
                    {"ip_address": ip_address, "endpoint": endpoint}
                )
            else:
                # First request in this window
                expires_at = now + timedelta(minutes=window_minutes)
                db.execute(
                    text("""
                        INSERT INTO rate_limits (ip_address, endpoint, count, first_request_at, expires_at)
                        VALUES (:ip_address, :endpoint, 1, :now, :expires_at)
                        ON CONFLICT (ip_address, endpoint) 
                        DO UPDATE SET 
                            count = 1,
                            first_request_at = :now,
                            expires_at = :expires_at,
                            updated_at = CURRENT_TIMESTAMP
                    """),
                    {
                        "ip_address": ip_address,
                        "endpoint": endpoint,
                        "now": now,
                        "expires_at": expires_at
                    }
                )

            db.commit()
            return True, 0, None

        except Exception as e:
            db.rollback()
            self.security_logger.error(
                "Rate limiting database error",
                extra={
                    "error": str(e),
                    "ip_address": ip_address,
                    "endpoint": endpoint
                }
            )
            # On error, allow the request (fail open)
            return True, 0, None
        finally:
            db.close()

    async def _get_rate_limit_status(self, ip_address: str, endpoint: str) -> tuple[bool, int, datetime]:
        """Get current rate limit status for headers"""
        max_requests, window_minutes = self.rate_limits[endpoint]

        db_gen = get_db()
        db: Session = next(db_gen)

        try:
            now = datetime.now(timezone.utc)

            result = db.execute(
                text("""
                    SELECT count, expires_at
                    FROM rate_limits 
                    WHERE ip_address = :ip_address 
                    AND endpoint = :endpoint 
                    AND expires_at > :now
                """),
                {
                    "ip_address": ip_address,
                    "endpoint": endpoint,
                    "now": now
                }
            ).fetchone()

            if result:
                current_count, expires_at = result
                return True, current_count, expires_at

            return True, 0, None

        except Exception:
            return True, 0, None
        finally:
            db.close()

    async def _cleanup_expired_entries(self, db: Session):
        """Clean up expired rate limit entries"""
        try:
            now = datetime.now(timezone.utc)
            result = db.execute(
                text("DELETE FROM rate_limits WHERE expires_at < :now"),
                {"now": now}
            )

            deleted_count = result.rowcount
            if deleted_count > 0:
                self.security_logger.debug(
                    f"Cleaned up {deleted_count} expired rate limit entries"
                )
        except Exception as e:
            self.security_logger.warning(
                f"Failed to cleanup expired rate limits: {e}"
            )

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address"""
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip

        return request.client.host if request.client else "unknown"

class InputSanitizationMiddleware(BaseHTTPMiddleware):
    """
    Input sanitization and validation middleware
    Prevents malicious input and validates URL parameters
    """

    def __init__(self, app):
        super().__init__(app)
        self.security_logger = get_security_logger()

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Sanitize URL parameters
        await self._sanitize_query_params(request)

        # Process request
        response = await call_next(request)
        return response

    async def _sanitize_query_params(self, request: Request):
        """Sanitize and validate URL query parameters"""

        dangerous_patterns = [
            '<script', 'javascript:', 'data:', 'vbscript:', 'onload=',
            'onerror=', 'onclick=', '<?php', '<%', 'eval(', 'alert(',
            'document.cookie', 'document.write', 'window.location'
        ]

        for key, value in request.query_params.items():
            # Check for dangerous patterns
            value_lower = str(value).lower()
            for pattern in dangerous_patterns:
                if pattern in value_lower:
                    self.security_logger.warning(
                        f"Dangerous pattern detected in query parameter",
                        extra={
                            'parameter': key,
                            'pattern': pattern,
                            'client_ip': self._get_client_ip(request),
                            'path': request.url.path,
                            'user_agent': request.headers.get('user-agent', 'unknown')
                        }
                    )

                    log_security_event(
                        event_type="malicious_input",
                        action="query_parameter_attack",
                        result="blocked",
                        client_ip=self._get_client_ip(request),
                        parameter=key,
                        pattern=pattern
                    )

                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Invalid query parameter detected"
                    )

            # Length validation
            if len(str(value)) > 1000:  # Reasonable limit
                self.security_logger.warning(
                    f"Excessively long query parameter detected",
                    extra={
                        'parameter': key,
                        'length': len(str(value)),
                        'client_ip': self._get_client_ip(request)
                    }
                )

                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Query parameter too long"
                )

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address"""
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return request.client.host if request.client else "unknown"


# CSRF Token Generation Utility
def generate_csrf_token() -> str:
    """Generate a secure CSRF token"""
    return secrets.token_urlsafe(32)

class SecurityLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for security-focused request/response logging
    Tracks all API requests for audit and security monitoring
    """

    def __init__(self, app, log_requests: bool = True):
        super().__init__(app)
        self.log_requests = log_requests
        self.api_logger = get_api_logger()
        self.security_logger = get_security_logger()

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Generate correlation ID for request tracking
        correlation_id = str(uuid.uuid4())

        # Extract security-relevant information
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("user-agent", "unknown")
        request_method = request.method
        request_path = str(request.url.path)

        # Start timing
        start_time = time.time()

        # Log incoming request (API endpoints only)
        if self.log_requests and request_path.startswith("/api/"):
            self.api_logger.info(
                f"Incoming {request_method} request to {request_path}",
                extra={
                    'correlation_id': correlation_id,
                    'method': request_method,
                    'path': request_path,
                    'client_ip': client_ip,
                    'user_agent': user_agent,
                    'query_params': dict(request.query_params),
                    'event_type': 'api_request'
                }
            )

        # Process request
        try:
            response = await call_next(request)
            processing_time = time.time() - start_time

            # Log response
            if self.log_requests and request_path.startswith("/api/"):
                self.api_logger.info(
                    f"Response {response.status_code} for {request_method} {request_path}",
                    extra={
                        'correlation_id': correlation_id,
                        'method': request_method,
                        'path': request_path,
                        'status_code': response.status_code,
                        'processing_time_ms': round(processing_time * 1000, 2),
                        'client_ip': client_ip,
                        'event_type': 'api_response'
                    }
                )

            # Log security events for suspicious activities
            self._log_security_events(request, response, client_ip, correlation_id)

            return response

        except Exception as e:
            processing_time = time.time() - start_time

            # Log error
            self.api_logger.error(
                f"Request failed: {request_method} {request_path}",
                extra={
                    'correlation_id': correlation_id,
                    'method': request_method,
                    'path': request_path,
                    'error_type': type(e).__name__,
                    'processing_time_ms': round(processing_time * 1000, 2),
                    'client_ip': client_ip,
                    'event_type': 'api_error'
                },
                exc_info=True
            )

            # Log security event for errors
            log_security_event(
                event_type="api_error",
                action=f"{request_method} {request_path}",
                result="error",
                correlation_id=correlation_id,
                client_ip=client_ip,
                error_type=type(e).__name__
            )

            raise

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request"""
        # Check for forwarded headers (common in reverse proxy setups)
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip

        return request.client.host if request.client else "unknown"

    def _log_security_events(self, request: Request, response: Response,
                             client_ip: str, correlation_id: str):
        """Log security-relevant events"""

        # Log authentication attempts
        if request.url.path.startswith("/api/v1/auth/"):
            if response.status_code == 200:
                log_security_event(
                    event_type="authentication",
                    action=f"{request.method} {request.url.path}",
                    result="success",
                    correlation_id=correlation_id,
                    client_ip=client_ip
                )
            elif response.status_code in [401, 403]:
                log_security_event(
                    event_type="authentication",
                    action=f"{request.method} {request.url.path}",
                    result="failure",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    status_code=response.status_code
                )

        # Log failed requests (potential attacks)
        if response.status_code == 404 and request.url.path.startswith("/api/"):
            self.security_logger.warning(
                f"API endpoint not found: {request.method} {request.url.path}",
                extra={
                    'correlation_id': correlation_id,
                    'client_ip': client_ip,
                    'user_agent': request.headers.get("user-agent"),
                    'event_type': 'endpoint_not_found'
                }
            )

        # Log rate limiting violations (if implemented)
        if response.status_code == 429:
            log_security_event(
                event_type="rate_limit",
                action=f"{request.method} {request.url.path}",
                result="violated",
                correlation_id=correlation_id,
                client_ip=client_ip
            )