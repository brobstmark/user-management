# File: backend/api/v1/frontend_logs.py
"""
Frontend Logging Endpoint
Integrates frontend logs with existing secure backend logging system
"""
from datetime import datetime
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from pydantic import BaseModel, Field, validator
from sqlalchemy.orm import Session
import inspect

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
security_optional = HTTPBearer(auto_error=False)  # no error if header is missing

RESERVED_LOGRECORD_KEYS = {
    "name","msg","args","levelname","levelno",
    "pathname","filename","module","lineno","funcName",
    "created","msecs","relativeCreated","thread","threadName",
    "process","processName","stack_info","exc_info","exc_text","asctime"
}

def safe_client_extra(d: dict) -> dict:
    """Wrap/rename client fields so they don't collide with Python logging."""
    clean = {}
    for k, v in d.items():
        if k in ("level", "message"):  # those are used by your logger call
            continue
        new_key = f"client_{k}" if k in RESERVED_LOGRECORD_KEYS else k
        if isinstance(v, (str, int, float, bool)) or v is None:
            clean[new_key] = v
        else:
            clean[new_key] = str(v)
    return {"client": clean}

async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_optional),
    db: Session = Depends(get_db),
):
    """
    Return the current user if an Authorization header is present & valid.
    If there's no header (anonymous page), return None.
    """
    if credentials is None:
        return None

    try:
        # Call your existing helper with the *credentials*, not the request
        result = get_current_user(credentials=credentials, db=db)
        if inspect.isawaitable(result):
            result = await result
        return result
    except HTTPException as e:
        # If token is missing/invalid, treat it as anonymous
        if e.status_code in (401, 403):
            return None
        raise

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
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """
    Accepts frontend log batches (works for anonymous users).
    Never throws to the client; logs internally and returns a summary.
    Adds two guardrails:
      - Origin allowlist (blocks cross-site spam)
      - Batch size cap (prevents flooding)
    """

    # ---------- helpers (scoped locally so this is truly copy-paste) ----------
    RESERVED_LOGRECORD_KEYS = {
        "name", "msg", "args", "levelname", "levelno",
        "pathname", "filename", "module", "lineno", "funcName",
        "created", "msecs", "relativeCreated", "thread", "threadName",
        "process", "processName", "stack_info", "exc_info", "exc_text", "asctime",
    }

    def safe_client_extra(d: dict) -> dict:
        """
        Make client payload safe for Python logging:
        - rename keys that collide with LogRecord fields (e.g., 'module')
        - coerce non-primitive values to string
        - nest everything under 'client' to avoid top-level collisions
        - skip message/level duplicates
        """
        cleaned = {}
        for k, v in (d or {}).items():
            if k in ("message", "level"):
                continue
            new_k = f"client_{k}" if k in RESERVED_LOGRECORD_KEYS else k
            if isinstance(v, (str, int, float, bool)) or v is None:
                cleaned[new_k] = v
            else:
                cleaned[new_k] = str(v)
        return {"client": cleaned}
    # -------------------------------------------------------------------------

    client_ip = request.client.host if request.client else "unknown"
    request_ua = (request.headers.get("user-agent") or "Unknown")[:200]
    user_id = current_user.id if current_user else None
    # user_email reserved if you wish to include later

    # ---------- A) Origin allowlist: only accept from your own site(s) ----------
    try:
        from urllib.parse import urlparse
        from backend.config.settings import settings

        allowed_origins = set()
        for url in (getattr(settings, "FRONTEND_URL", None), getattr(settings, "API_URL", None)):
            if url:
                pu = urlparse(url)
                if pu.scheme and pu.netloc:
                    allowed_origins.add(f"{pu.scheme}://{pu.netloc}")

        # Helpful for local dev; remove if you prefer stricter policy
        allowed_origins.update({"http://localhost:8000", "http://127.0.0.1:8000"})

        # Prefer Origin, fall back to Referer (origin portion)
        hdr_origin = request.headers.get("origin")
        if not hdr_origin:
            ref = request.headers.get("referer")
            if ref:
                pr = urlparse(ref)
                if pr.scheme and pr.netloc:
                    hdr_origin = f"{pr.scheme}://{pr.netloc}"

        if hdr_origin and hdr_origin not in allowed_origins:
            api_logger.warning("Dropped frontend logs from disallowed origin", extra={
                "action": "frontend_log_dropped_origin",
                "origin": hdr_origin,
                "allowed": list(allowed_origins),
                "ip_address": client_ip,
            })
            return LogResponse(success=True, processed_count=0, message="Dropped by origin policy")
    except Exception as e:
        # Never let policy evaluation break the endpoint
        api_logger.warning("Origin policy evaluation failed", extra={
            "action": "frontend_origin_policy_error",
            "error_type": type(e).__name__,
            "error_message": str(e)[:300],
            "ip_address": client_ip,
        })

    # Envelope log for the batch
    api_logger.info("Frontend log batch received", extra={
        "action": "frontend_log_submission",
        "log_count": len(log_batch.logs or []),
        "user_id": user_id,
        "ip_address": client_ip,
        "user_agent": request_ua,
        "source": "frontend_logging_endpoint",
    })

    processed_count = 0
    failed_count = 0

    # ---------- B) Batch size cap ----------
    MAX_BATCH = 200  # adjust as you like
    entries = list(log_batch.logs or [])
    if len(entries) > MAX_BATCH:
        api_logger.warning("Trimming oversized frontend log batch", extra={
            "action": "frontend_log_batch_trim",
            "original_count": len(entries),
            "trimmed_to": MAX_BATCH,
            "user_id": user_id,
            "ip_address": client_ip,
        })
        entries = entries[:MAX_BATCH]

    # Process each log entry safely
    for entry in entries:
        try:
            # Choose destination logger (fallback to 'api')
            try:
                logger_type = _determine_logger_type(entry)
            except Exception:
                logger_type = "api"
            logger = _get_logger_by_type(logger_type)

            # Build safe "extra" payload
            base_extra = {
                "source": "frontend",
                "user_id": user_id,
                "ip_address": client_ip,
                "user_agent": (entry.user_agent or request_ua)[:200],
            }
            client_payload = {
                "url": entry.url,
                "session_id": entry.session_id,
                "timestamp": entry.timestamp,
                **(entry.context or {}),
            }

            # Keep your sanitizer, but never let it crash
            try:
                _sanitize_log_context(client_payload)
            except Exception:
                pass

            safe_extra = {**base_extra, **safe_client_extra(client_payload)}

            # Message + level (with safe defaults + truncation)
            msg = str(getattr(entry, "message", "") or "frontend_log").strip()
            if len(msg) > 2000:
                msg = msg[:2000]

            lvl = str(getattr(entry, "level", "INFO") or "INFO").upper()
            if lvl == "DEBUG":
                logger.debug(msg, extra=safe_extra)
            elif lvl in ("WARN", "WARNING"):
                logger.warning(msg, extra=safe_extra)
            elif lvl == "ERROR":
                logger.error(msg, extra=safe_extra)
            elif lvl == "CRITICAL":
                logger.critical(msg, extra=safe_extra)
            else:
                logger.info(msg, extra=safe_extra)

            # Optional special handling; swallow its failures
            try:
                _handle_special_log_types(entry, safe_extra, user_id, client_ip)
            except Exception as e2:
                api_logger.warning("Frontend log special handler failed", extra={
                    "action": "frontend_log_special_handler_error",
                    "user_id": user_id,
                    "ip_address": client_ip,
                    "error_type": type(e2).__name__,
                    "error_message": str(e2)[:500],
                    **safe_client_extra({"handler_error": str(e2)[:200]}),
                })

            processed_count += 1

        except Exception as e:
            failed_count += 1
            api_logger.error("Error processing individual frontend log", extra={
                "action": "frontend_log_processing_error",
                "user_id": user_id,
                "ip_address": client_ip,
                "error_type": type(e).__name__,
                "error_message": str(e)[:500],
                "processed_count": processed_count,
                "failed_count": failed_count,
                **safe_client_extra({"exception": str(e)[:200]}),
            })
            # keep going

    # Batch summary
    result_msg = f"Processed {processed_count} log(s)" + (f", {failed_count} failed" if failed_count else "")
    api_logger.info("Frontend logs processed", extra={
        "action": "frontend_log_processing_complete",
        "processed_count": processed_count,
        "failed_count": failed_count,
        "user_id": user_id,
        "ip_address": client_ip,
    })

    # Mailbox behavior: always succeed to the client
    return LogResponse(
        success=(failed_count == 0),
        processed_count=processed_count,
        message=result_msg,
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