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
from backend.utils.logging import get_security_logger, log_security_event

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