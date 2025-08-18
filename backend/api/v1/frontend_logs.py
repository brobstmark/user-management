# File: backend/api/v1/frontend_logs.py
"""
Frontend Logging Endpoint
Integrates frontend logs with existing secure backend logging system
"""
from datetime import datetime
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field, validator
from sqlalchemy.orm import Session

from backend.config.database import get_db
from backend.core.dependencies import get_current_user
from backend.models.user import User
from backend.utils.logging import (
    get_auth_logger,
    get_security_logger,
    get_api_logger,
    log_security_event,
    log_audit_event
)

router = APIRouter()

# Initialize loggers
auth_logger = get_auth_logger()
security_logger = get_security_logger()
api_logger = get_api_logger()


class FrontendLogEntry(BaseModel):
    """Frontend log entry schema with validation"""
    timestamp: str = Field(..., description="ISO timestamp of log event")
    level: str = Field(..., description="Log level (DEBUG, INFO, WARN, ERROR)")
    message: str = Field(..., max_length=500, description="Log message (max 500 chars)")
    context: Dict[str, Any] = Field(default_factory=dict, description="Additional context data")
    url: str = Field(..., max_length=2000, description="Frontend URL where log occurred")
    user_agent: Optional[str] = Field(None, max_length=500, description="User agent string")
    session_id: Optional[str] = Field(None, max_length=100, description="Frontend session ID")
    source: str = Field(default="frontend", description="Log source identifier")

    @validator('level')
    def validate_level(cls, v):
        allowed_levels = ['DEBUG', 'INFO', 'WARN', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in allowed_levels:
            raise ValueError(f'Invalid log level. Must be one of: {allowed_levels}')
        return v.upper()

    @validator('message')
    def validate_message(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Log message cannot be empty')
        return v.strip()


class FrontendLogBatch(BaseModel):
    """Batch of frontend log entries"""
    logs: List[FrontendLogEntry] = Field(..., max_items=50, description="Log entries (max 50 per batch)")
    client_info: Dict[str, Any] = Field(default_factory=dict, description="Client information")

    @validator('logs')
    def validate_logs_not_empty(cls, v):
        if not v:
            raise ValueError('At least one log entry is required')
        return v


class LogResponse(BaseModel):
    """Response for log submission"""
    success: bool = Field(..., description="Whether logs were processed successfully")
    processed_count: int = Field(..., description="Number of logs processed")
    message: str = Field(..., description="Response message")


@router.post("/frontend", response_model=LogResponse, status_code=status.HTTP_200_OK)
async def submit_frontend_logs(
        log_batch: FrontendLogBatch,
        request: Request,
        db: Session = Depends(get_db),
        current_user: Optional[User] = Depends(get_current_user)
        # Optional - some logs may be from unauthenticated users
):
    """
    Submit frontend logs to backend logging system

    Integrates with existing secure logging infrastructure:
    - Uses existing PII redaction and security filters
    - Routes to appropriate log types (auth, security, api)
    - Maintains audit trail for security events
    - Rate limiting and validation built-in
    """
    client_ip = request.client.host if request.client else "unknown"
    user_id = current_user.id if current_user else None
    user_email = current_user.email if current_user else None

    # Log the incoming frontend log submission
    api_logger.info("Frontend log batch received", extra={
        'action': 'frontend_log_submission',
        'log_count': len(log_batch.logs),
        'user_id': user_id,
        'ip_address': client_ip,
        'user_agent': request.headers.get('user-agent', 'Unknown')[:200],
        'source': 'frontend_logging_endpoint'
    })

    processed_count = 0

    try:
        for log_entry in log_batch.logs:
            # Determine which logger to use based on log context and content
            logger_type = _determine_logger_type(log_entry)
            logger = _get_logger_by_type(logger_type)

            # Prepare log context with frontend-specific information
            log_context = {
                'source': 'frontend',
                'frontend_url': log_entry.url,
                'frontend_session_id': log_entry.session_id,
                'user_id': user_id,
                'ip_address': client_ip,
                'user_agent': log_entry.user_agent,
                'frontend_timestamp': log_entry.timestamp,
                **log_entry.context  # Include original context
            }

            # Remove sensitive fields that shouldn't be in context
            _sanitize_log_context(log_context)

            # Log using appropriate level
            log_level = log_entry.level.upper()
            if log_level in ['DEBUG']:
                logger.debug(log_entry.message, extra=log_context)
            elif log_level in ['INFO']:
                logger.info(log_entry.message, extra=log_context)
            elif log_level in ['WARN', 'WARNING']:
                logger.warning(log_entry.message, extra=log_context)
            elif log_level in ['ERROR']:
                logger.error(log_entry.message, extra=log_context)
            elif log_level in ['CRITICAL']:
                logger.critical(log_entry.message, extra=log_context)

            # Handle special log types that need additional processing
            _handle_special_log_types(log_entry, log_context, user_id, client_ip)

            processed_count += 1

    except Exception as e:
        # Log the error in processing frontend logs
        api_logger.error("Error processing frontend logs", extra={
            'action': 'frontend_log_processing_error',
            'user_id': user_id,
            'ip_address': client_ip,
            'error_type': type(e).__name__,
            'error_message': str(e),
            'processed_count': processed_count,
            'total_logs': len(log_batch.logs)
        })

        log_security_event(
            event_type="frontend_logging",
            action="log_processing",
            result="error",
            user_id=user_id,
            ip_address=client_ip,
            error_type=type(e).__name__
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error processing logs"
        )

    # Log successful processing
    api_logger.info("Frontend logs processed successfully", extra={
        'action': 'frontend_log_processing_complete',
        'processed_count': processed_count,
        'user_id': user_id,
        'ip_address': client_ip
    })

    return LogResponse(
        success=True,
        processed_count=processed_count,
        message=f"Successfully processed {processed_count} log entries"
    )


def _determine_logger_type(log_entry: FrontendLogEntry) -> str:
    """
    Determine which backend logger to use based on log content
    """
    message_lower = log_entry.message.lower()
    context = log_entry.context

    # Security-related events
    security_keywords = [
        'security', 'auth', 'login', 'logout', 'token', 'password',
        'verification', 'permission', 'unauthorized', 'forbidden',
        'csrf', 'xss', 'injection', 'attack', 'suspicious'
    ]

    # Authentication-related events
    auth_keywords = [
        'login', 'logout', 'register', 'authenticate', 'verification',
        'token', 'session', 'credential'
    ]

    # Check context for event types
    if context.get('security_event') or context.get('auth_event'):
        return 'security' if context.get('security_event') else 'auth'

    # Check message content
    if any(keyword in message_lower for keyword in security_keywords):
        return 'security'
    elif any(keyword in message_lower for keyword in auth_keywords):
        return 'auth'
    else:
        return 'api'  # Default to API logger for general frontend logs


def _get_logger_by_type(logger_type: str):
    """Get logger instance by type"""
    loggers = {
        'auth': auth_logger,
        'security': security_logger,
        'api': api_logger
    }
    return loggers.get(logger_type, api_logger)


def _sanitize_log_context(context: Dict[str, Any]) -> None:
    """
    Sanitize log context to remove/mask sensitive data
    Note: The PII filters will handle most of this, but we can pre-clean obvious sensitive keys
    """
    sensitive_keys = [
        'password', 'token', 'secret', 'key', 'credential',
        'authorization', 'cookie', 'session_token'
    ]

    for key in list(context.keys()):
        if any(sensitive in key.lower() for sensitive in sensitive_keys):
            context[key] = '[REDACTED]'


def _handle_special_log_types(
        log_entry: FrontendLogEntry,
        log_context: Dict[str, Any],
        user_id: Optional[int],
        client_ip: str
) -> None:
    """
    Handle special log types that need additional processing
    """
    context = log_entry.context

    # Handle security events
    if context.get('security_event'):
        event_type = context.get('event_type', 'frontend_security')
        action = context.get('action', 'unknown')
        result = context.get('result', 'unknown')

        log_security_event(
            event_type=event_type,
            action=action,
            result=result,
            user_id=user_id,
            ip_address=client_ip,
            source='frontend'
        )

    # Handle authentication events
    if context.get('auth_event'):
        event_type = context.get('event_type', 'frontend_auth')
        action = context.get('action', 'unknown')
        result = context.get('result', 'unknown')

        log_security_event(
            event_type=event_type,
            action=action,
            result=result,
            user_id=user_id,
            ip_address=client_ip,
            source='frontend'
        )

    # Handle JavaScript errors (these are important for security)
    if log_entry.level.upper() == 'ERROR' and 'javascript' in log_entry.message.lower():
        log_security_event(
            event_type="frontend_error",
            action="javascript_error",
            result="error",
            user_id=user_id,
            ip_address=client_ip,
            error_message=log_entry.message[:200],  # Limit error message length
            frontend_url=log_entry.url
        )

    # Handle potential security violations
    suspicious_patterns = ['xss', 'injection', 'csrf', 'unauthorized', 'forbidden']
    if any(pattern in log_entry.message.lower() for pattern in suspicious_patterns):
        log_security_event(
            event_type="frontend_security",
            action="suspicious_activity",
            result="detected",
            user_id=user_id,
            ip_address=client_ip,
            suspicious_content=log_entry.message[:200],
            frontend_url=log_entry.url
        )