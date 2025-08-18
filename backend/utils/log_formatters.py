"""
Custom Log Formatters for Different Environments
Handles development-friendly and production-ready log formats
"""
import json
import logging
import traceback
from datetime import datetime
from typing import Dict, Any, Optional, Union, List, Tuple


class DevelopmentFormatter(logging.Formatter):
    """
    Human-readable formatter for development environment
    Includes colors, emojis, and detailed information
    """

    # Color codes for different log levels
    COLORS = {
        'DEBUG': '\033[36m',  # Cyan
        'INFO': '\033[32m',  # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',  # Red
        'CRITICAL': '\033[35m',  # Magenta
        'RESET': '\033[0m'  # Reset color
    }

    # Emojis for different log levels
    EMOJIS = {
        'DEBUG': '🔍',
        'INFO': 'ℹ️ ',
        'WARNING': '⚠️ ',
        'ERROR': '❌',
        'CRITICAL': '🚨'
    }

    def __init__(self, include_colors: bool = True):
        super().__init__()
        self.include_colors = include_colors

    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record for development environment
        """
        # Get color and emoji for log level
        color = self.COLORS.get(record.levelname, '') if self.include_colors else ''
        reset = self.COLORS['RESET'] if self.include_colors else ''
        emoji = self.EMOJIS.get(record.levelname, '')

        # Format timestamp
        timestamp = datetime.fromtimestamp(record.created).strftime('%H:%M:%S.%f')[:-3]

        # Format basic message
        message = f"{color}{emoji} {timestamp} | {record.levelname:<8} | {record.name:<20} | {record.getMessage()}{reset}"

        # Add exception information if present
        if record.exc_info:
            exc_text = self.formatException(record.exc_info)
            message += f"\n{color}📋 Exception Details:\n{exc_text}{reset}"

        # Add extra context if available
        extra_info = self._get_extra_info(record)
        if extra_info:
            message += f"\n{color}📎 Context: {extra_info}{reset}"

        return message

    def _get_extra_info(self, record: logging.LogRecord) -> str:
        """
        Extract extra information from log record and sanitize it
        """
        # Standard logging attributes to exclude
        standard_attrs = {
            'name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 'filename',
            'module', 'lineno', 'funcName', 'created', 'msecs', 'relativeCreated',
            'thread', 'threadName', 'processName', 'process', 'message', 'exc_info',
            'exc_text', 'stack_info'
        }

        extra: Dict[str, Any] = {}
        for key, value in record.__dict__.items():
            if key not in standard_attrs and not key.startswith('_'):
                extra[key] = value

        if not extra:
            return ""

        # ✅ NEW: Sanitize the extra data before displaying
        try:
            from backend.utils.log_filters import PIIFilter
            pii_filter = PIIFilter()
            sanitized_extra = pii_filter._sanitize_dict(extra)
            return self._safe_json_dumps(sanitized_extra)
        except Exception:
            # Fallback to original behavior if sanitization fails
            return self._safe_json_dumps(extra)

    def _safe_json_dumps(self, data: Dict[str, Any]) -> str:
        """
        Safely serialize data to JSON with error handling
        """
        try:
            return json.dumps(data, default=str)
        except (TypeError, ValueError):
            # Fallback for non-serializable data
            return str(data)


class ProductionFormatter(logging.Formatter):
    """
    JSON formatter for production environment
    Machine-readable format suitable for log aggregation services
    """

    def __init__(self, include_sensitive_data: bool = False):
        super().__init__()
        self.include_sensitive_data = include_sensitive_data

    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record as JSON for production environment
        """
        # Basic log entry structure - explicitly typed as flexible dictionary
        log_entry: Dict[str, Any] = {}

        # Add basic fields
        log_entry['timestamp'] = datetime.fromtimestamp(record.created).isoformat()
        log_entry['level'] = record.levelname
        log_entry['logger'] = record.name
        log_entry['message'] = record.getMessage()
        log_entry['module'] = record.module
        log_entry['function'] = record.funcName
        log_entry['line'] = record.lineno

        # Add process/thread info for debugging
        if hasattr(record, 'process') and hasattr(record, 'thread'):
            process_info: Dict[str, Any] = {
                'id': record.process,
                'name': getattr(record, 'processName', 'Unknown')
            }
            thread_info: Dict[str, Any] = {
                'id': record.thread,
                'name': getattr(record, 'threadName', 'Unknown')
            }
            log_entry['process'] = process_info
            log_entry['thread'] = thread_info

        # Add exception information if present
        if record.exc_info:
            exception_info: Dict[str, Optional[str]] = {
                'type': record.exc_info[0].__name__ if record.exc_info[0] else None,
                'message': str(record.exc_info[1]) if record.exc_info[1] else None,
                'traceback': self.formatException(record.exc_info) if self.include_sensitive_data else '[REDACTED]'
            }
            log_entry['exception'] = exception_info

        # Add extra context
        extra_data = self._get_extra_data(record)
        if extra_data:
            log_entry['extra'] = extra_data

        # Add correlation ID if available (for tracing requests)
        if hasattr(record, 'correlation_id'):
            log_entry['correlation_id'] = record.correlation_id

        # Add user context if available (non-sensitive parts only)
        if hasattr(record, 'user_id') and not self.include_sensitive_data:
            log_entry['user_id'] = record.user_id

        return self._safe_json_dumps(log_entry)

    def _get_extra_data(self, record: logging.LogRecord) -> Dict[str, Any]:
        """
        Extract extra data from log record, excluding standard attributes
        """
        standard_attrs = {
            'name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 'filename',
            'module', 'lineno', 'funcName', 'created', 'msecs', 'relativeCreated',
            'thread', 'threadName', 'processName', 'process', 'message', 'exc_info',
            'exc_text', 'stack_info', 'correlation_id', 'user_id'
        }

        extra: Dict[str, Any] = {}
        for key, value in record.__dict__.items():
            if key not in standard_attrs and not key.startswith('_'):
                extra[key] = value

        return extra

    def _safe_json_dumps(self, data: Dict[str, Any]) -> str:
        """
        Safely serialize data to JSON with error handling
        """
        try:
            return json.dumps(data, default=str, separators=(',', ':'))
        except (TypeError, ValueError) as e:
            # Fallback for non-serializable data
            return json.dumps({
                'error': 'Failed to serialize log data',
                'error_type': type(e).__name__,
                'message': str(data.get('message', 'Unknown message'))
            }, separators=(',', ':'))


class StagingFormatter(logging.Formatter):
    """
    Hybrid formatter for staging environment
    Combines readability of development with structure of production
    """

    def __init__(self):
        super().__init__()
        self.dev_formatter = DevelopmentFormatter(include_colors=False)
        self.prod_formatter = ProductionFormatter(include_sensitive_data=True)

    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record for staging environment
        """
        # For ERROR and CRITICAL, use JSON format for easier debugging
        if record.levelno >= logging.ERROR:
            return self.prod_formatter.format(record)

        # For other levels, use human-readable format
        return self.dev_formatter.format(record)


class AuditFormatter(logging.Formatter):
    """
    Special formatter for audit logs
    Includes additional security and compliance information
    """

    def __init__(self):
        super().__init__()

    def format(self, record: logging.LogRecord) -> str:
        """
        Format audit log record with security context
        """
        audit_entry: Dict[str, Any] = {}

        # Add audit fields
        audit_entry['timestamp'] = datetime.fromtimestamp(record.created).isoformat()
        audit_entry['event_type'] = getattr(record, 'event_type', 'unknown')
        audit_entry['action'] = getattr(record, 'action', record.getMessage())
        audit_entry['result'] = getattr(record, 'result', 'unknown')

        # Add optional fields only if they exist
        optional_fields = ['user_id', 'session_id', 'ip_address', 'user_agent', 'resource', 'correlation_id']
        for field in optional_fields:
            value = getattr(record, field, None)
            if value is not None:
                audit_entry[field] = value

        return self._safe_json_dumps(audit_entry)

    def _safe_json_dumps(self, data: Dict[str, Any]) -> str:
        """
        Safely serialize data to JSON with error handling
        """
        try:
            return json.dumps(data, default=str, separators=(',', ':'))
        except (TypeError, ValueError) as e:
            # Fallback for non-serializable data
            return json.dumps({
                'error': 'Failed to serialize audit data',
                'error_type': type(e).__name__,
                'timestamp': datetime.now().isoformat()
            }, separators=(',', ':'))


def get_formatter(environment: str, formatter_type: str = 'default') -> logging.Formatter:
    """
    Get appropriate formatter based on environment and type

    Args:
        environment: Current environment (development, staging, production)
        formatter_type: Type of formatter (default, audit)

    Returns:
        Configured logging formatter
    """
    if formatter_type == 'audit':
        return AuditFormatter()

    if environment == 'development':
        return DevelopmentFormatter(include_colors=True)
    elif environment == 'staging':
        return StagingFormatter()
    elif environment == 'production':
        return ProductionFormatter(include_sensitive_data=False)
    else:
        # Default to production formatter for unknown environments
        return ProductionFormatter(include_sensitive_data=False)


class ContextualLoggerAdapter(logging.LoggerAdapter):
    """
    Logger adapter that adds contextual information to all log records
    Useful for adding request IDs, user IDs, etc.
    """

    def __init__(self, logger: logging.Logger, extra: Dict[str, Any]):
        super().__init__(logger, extra)

    def process(self, msg: Any, kwargs: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        """
        Add extra context to log record
        """
        # Merge extra context
        extra = kwargs.get('extra', {})
        extra.update(self.extra)
        kwargs['extra'] = extra

        return msg, kwargs

    def with_context(self, **context) -> 'ContextualLoggerAdapter':
        """
        Create a new adapter with additional context

        Args:
            **context: Additional context to add

        Returns:
            New logger adapter with combined context
        """
        combined_extra = {**self.extra, **context}
        return ContextualLoggerAdapter(self.logger, combined_extra)