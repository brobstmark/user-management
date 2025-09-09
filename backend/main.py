"""
User Management System - FastAPI Application
Enhanced with Enterprise Secure Logging System
"""
import time
import uuid
from typing import Callable

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from backend.core.middleware import (
    SecurityHeadersMiddleware,
    InputSanitizationMiddleware,
    RateLimitingMiddleware,
    SecurityLoggingMiddleware
)
from backend.config.settings import settings
from backend.config.validation import validate_configuration
from backend.api.v1.router import api_router
from backend.utils.logging import (
    get_api_logger,
    get_security_logger,
    get_audit_logger,
    log_security_event,
    log_audit_event
)

# Initialize FastAPI app
app = FastAPI(
    title="User Management System API",
    description="A comprehensive user management system with authentication",
    version="1.0.0",
    debug=settings.DEBUG
)

# Get loggers (initialize first)
startup_logger = get_api_logger()
security_logger = get_security_logger()

# CORS middleware with dynamic origins (ADD FIRST - executes last)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add security headers middleware (ADD SECOND - executes third)
app.add_middleware(SecurityHeadersMiddleware)

# Add input sanitization middleware (ADD THIRD - executes second)
app.add_middleware(InputSanitizationMiddleware)

# Add rate limiting middleware (ADD FOURTH - executes second)
app.add_middleware(RateLimitingMiddleware)

# Add security logging middleware (ADD LAST - executes first)
app.add_middleware(
    SecurityLoggingMiddleware,
    log_requests=True
)

# Add config endpoint before main API router
from backend.api.config import router as config_router

app.include_router(config_router, prefix="/api", tags=["config"])

# Include API router
app.include_router(api_router, prefix="/api/v1")

# Serve frontend static files
app.mount("/frontend", StaticFiles(directory="frontend"), name="frontend")


@app.get("/")
async def root():
    """Root endpoint with environment info"""
    startup_logger.info("Root endpoint accessed")
    return {
        "message": "User Management System API",
        "version": "1.0.0",
        "environment": settings.ENVIRONMENT,
        "docs": "/docs" if settings.DEBUG else None
    }


@app.exception_handler(404)
async def custom_404_handler(request: Request, exc):
    """Custom 404 handler for SPA routing with security logging"""
    client_ip = request.client.host if request.client else "unknown"

    # Log 404s for security monitoring
    if request.url.path.startswith("/api/"):
        security_logger.warning(
            f"API endpoint not found: {request.method} {request.url.path}",
            extra={
                'client_ip': client_ip,
                'user_agent': request.headers.get("user-agent"),
                'path': str(request.url.path),
                'method': request.method,
                'event_type': 'api_404'
            }
        )

        return JSONResponse(
            status_code=404,
            content={"detail": "API endpoint not found"}
        )
    else:
        # Log frontend 404s (potential reconnaissance)
        startup_logger.info(
            f"Frontend resource not found: {request.url.path}",
            extra={
                'client_ip': client_ip,
                'path': str(request.url.path),
                'event_type': 'frontend_404'
            }
        )

    return JSONResponse(
        status_code=404,
        content={"detail": "Page not found"}
    )


@app.exception_handler(500)
async def custom_500_handler(request: Request, exc):
    """Custom 500 handler with security logging"""
    client_ip = request.client.host if request.client else "unknown"
    correlation_id = str(uuid.uuid4())

    # Log internal server errors
    startup_logger.error(
        f"Internal server error: {request.method} {request.url.path}",
        extra={
            'correlation_id': correlation_id,
            'client_ip': client_ip,
            'path': str(request.url.path),
            'method': request.method,
            'error_type': type(exc).__name__,
            'event_type': 'internal_error'
        },
        exc_info=True
    )

    # Log security event
    log_security_event(
        event_type="application_error",
        action=f"{request.method} {request.url.path}",
        result="internal_error",
        correlation_id=correlation_id,
        client_ip=client_ip,
        error_type=type(exc).__name__
    )

    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "correlation_id": correlation_id if settings.DEBUG else None
        }
    )


# Application lifecycle events with secure logging
@app.on_event("startup")
async def startup_event():
    """Application startup with comprehensive logging"""
    startup_logger.info(
        "User Management System starting up",
        extra={
            'environment': settings.ENVIRONMENT,
            'debug_mode': settings.DEBUG,
            'allowed_origins_count': len(settings.ALLOWED_ORIGINS),
            'email_configured': bool(settings.EMAIL_USERNAME),
            'version': '1.0.0',
            'event_type': 'application_startup'
        }
    )

    # Log audit event for application startup
    log_audit_event(
        action="application_startup",
        resource="system",
        result="success",
        environment=settings.ENVIRONMENT,
        version="1.0.0"
    )

    # Log security configuration
    log_security_event(
        event_type="configuration",
        action="cors_setup",
        result="configured",
        origins_count=len(settings.ALLOWED_ORIGINS),
        environment=settings.ENVIRONMENT
    )

    # Console output for development (with security logging active)
    if settings.DEBUG:
        startup_logger.info("Debug endpoints available", extra={
            'docs_url': 'http://localhost:8000/docs',
            'frontend_url': 'http://localhost:8000/frontend/',
            'config_url': 'http://localhost:8000/api/config',
            'event_type': 'debug_info'
        })


@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown with logging"""
    startup_logger.info(
        "User Management System shutting down",
        extra={
            'environment': settings.ENVIRONMENT,
            'version': '1.0.0',
            'event_type': 'application_shutdown'
        }
    )

    # Log audit event for application shutdown
    log_audit_event(
        action="application_shutdown",
        resource="system",
        result="success",
        environment=settings.ENVIRONMENT
    )

# Run validation on import
validate_configuration()