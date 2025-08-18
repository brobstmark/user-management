"""
Secure Logging System for User Management Application
Production-ready logging with PII protection and environment awareness
"""
import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Dict, Optional, Any, List

from backend.utils.log_filters import create_security_filters, PIIFilter
from backend.utils.log_formatters import get_formatter, ContextualLoggerAdapter


class SecureLoggingConfig:
    """
    Centralized logging configuration with security and environment awareness
    """

    def __init__(self, environment: str = "production", debug: bool = False):
        self.environment = environment
        self.debug = debug
        self.is_production = environment == "production"
        self.log_directory = Path("logs")

        # Default log levels by environment
        self.default_levels = {
            'development': logging.DEBUG,
            'staging': logging.INFO,
            'production': logging.WARNING
        }

        # Logger configurations
        self.logger_configs = {
            'auth': {'level': logging.INFO, 'file': 'auth.log'},
            'email': {'level': logging.INFO, 'file': 'email.log'},
            'api': {'level': logging.INFO, 'file': 'api.log'},
            'security': {'level': logging.WARNING, 'file': 'security.log'},
            'audit': {'level': logging.INFO, 'file': 'audit.log'},
            'error': {'level': logging.ERROR, 'file': 'error.log'}
        }

        self._setup_log_directory()
        self._configured_loggers = set()

    def _setup_log_directory(self):
        """Create log directory if it doesn't exist (production only)"""
        if self.is_production:
            self.log_directory.mkdir(parents=True, exist_ok=True)

    def get_logger(self, name: str, **context) -> logging.Logger:
        """
        Get a configured secure logger

        Args:
            name: Logger name (e.g., 'auth', 'email', 'api')
            **context: Additional context to add to all log messages

        Returns:
            Configured logger with security filters and formatters
        """
        logger = logging.getLogger(f"usermgmt.{name}")

        # Configure logger if not already done
        if name not in self._configured_loggers:
            self._configure_logger(logger, name)
            self._configured_loggers.add(name)

        # Return contextual adapter if context provided
        if context:
            return ContextualLoggerAdapter(logger, context)

        return logger

    def _configure_logger(self, logger: logging.Logger, name: str):
        """Configure a specific logger with handlers, filters, and formatters"""

        # Clear any existing handlers
        logger.handlers.clear()

        # Set log level
        config = self.logger_configs.get(name, {})
        level = config.get('level', self.default_levels.get(self.environment, logging.INFO))
        logger.setLevel(level)

        # Add console handler for development and staging
        if self.environment in ['development', 'staging']:
            console_handler = self._create_console_handler(name)
            logger.addHandler(console_handler)

        # Add file handler for staging and production
        if self.environment in ['staging', 'production']:
            file_handler = self._create_file_handler(name)
            if file_handler:
                logger.addHandler(file_handler)

        # Add error file handler for all environments (errors only)
        if name != 'error':  # Avoid recursion
            error_handler = self._create_error_handler()
            if error_handler:
                logger.addHandler(error_handler)

        # Add audit handler for security-related loggers
        if name in ['auth', 'security', 'audit']:
            audit_handler = self._create_audit_handler()
            if audit_handler:
                logger.addHandler(audit_handler)

        # Prevent propagation to root logger
        logger.propagate = False

    def _create_console_handler(self, logger_name: str) -> logging.StreamHandler:
        """Create console handler for development output"""
        handler = logging.StreamHandler(sys.stdout)

        # Set level - more verbose in development
        if self.environment == 'development':
            handler.setLevel(logging.DEBUG)
        else:
            handler.setLevel(logging.INFO)

        # Add formatter
        formatter = get_formatter(self.environment, 'default')
        handler.setFormatter(formatter)

        # Add security filters
        for filter_obj in create_security_filters(self.environment):
            handler.addFilter(filter_obj)

        return handler

    def _create_file_handler(self, logger_name: str) -> Optional[logging.handlers.RotatingFileHandler]:
        """Create rotating file handler for persistent logging"""
        try:
            config = self.logger_configs.get(logger_name, {})
            filename = config.get('file', f'{logger_name}.log')
            filepath = self.log_directory / filename

            # Rotating file handler (10MB max, keep 5 backups)
            handler = logging.handlers.RotatingFileHandler(
                filepath,
                maxBytes=10 * 1024 * 1024,  # 10MB
                backupCount=5,
                encoding='utf-8'
            )

            # Set level
            handler.setLevel(config.get('level', logging.INFO))

            # Add formatter (JSON for production)
            formatter = get_formatter(self.environment, 'default')
            handler.setFormatter(formatter)

            # Add security filters
            for filter_obj in create_security_filters(self.environment):
                handler.addFilter(filter_obj)

            return handler

        except Exception as e:
            # If file logging fails, log to stderr
            sys.stderr.write(f"Failed to create file handler for {logger_name}: {e}\n")
            return None

    def _create_error_handler(self) -> Optional[logging.handlers.RotatingFileHandler]:
        """Create dedicated error file handler"""
        try:
            filepath = self.log_directory / 'error.log'

            handler = logging.handlers.RotatingFileHandler(
                filepath,
                maxBytes=20 * 1024 * 1024,  # 20MB for errors
                backupCount=10,
                encoding='utf-8'
            )

            # Only handle ERROR and CRITICAL
            handler.setLevel(logging.ERROR)

            # Use production formatter for structured error logs
            formatter = get_formatter('production', 'default')
            handler.setFormatter(formatter)

            # Add security filters
            for filter_obj in create_security_filters(self.environment):
                handler.addFilter(filter_obj)

            return handler

        except Exception as e:
            sys.stderr.write(f"Failed to create error handler: {e}\n")
            return None

    def _create_audit_handler(self) -> Optional[logging.handlers.RotatingFileHandler]:
        """Create dedicated audit log handler for security events"""
        try:
            filepath = self.log_directory / 'audit.log'

            handler = logging.handlers.RotatingFileHandler(
                filepath,
                maxBytes=50 * 1024 * 1024,  # 50MB for audit logs
                backupCount=20,  # Keep more audit logs
                encoding='utf-8'
            )

            handler.setLevel(logging.INFO)

            # Use audit formatter
            formatter = get_formatter(self.environment, 'audit')
            handler.setFormatter(formatter)

            # Add security filters (but may be less restrictive for audit trails)
            pii_filter = PIIFilter()
            handler.addFilter(pii_filter)

            return handler

        except Exception as e:
            sys.stderr.write(f"Failed to create audit handler: {e}\n")
            return None


# Global logging configuration instance
_logging_config: Optional[SecureLoggingConfig] = None


def initialize_logging(environment: str = "production", debug: bool = False):
    """
    Initialize the global logging configuration

    Args:
        environment: Current environment (development, staging, production)
        debug: Enable debug mode
    """
    global _logging_config
    _logging_config = SecureLoggingConfig(environment, debug)

    # Configure root logger to catch any unconfigured loggers
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.WARNING)

    # Remove default handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add minimal handler for uncaught logs
    if environment == 'development':
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(logging.WARNING)
        formatter = get_formatter(environment, 'default')
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)


def get_logger(name: str, **context) -> logging.Logger:
    """
    Get a configured secure logger

    Args:
        name: Logger name (auth, email, api, security, audit, error)
        **context: Additional context for all log messages

    Returns:
        Configured secure logger

    Example:
        logger = get_logger('auth', user_id=123, action='login')
        logger.info("User login attempt")
    """
    global _logging_config

    if _logging_config is None:
        # Auto-initialize with safe defaults
        initialize_logging()

    return _logging_config.get_logger(name, **context)


# Convenience functions for common loggers
def get_auth_logger(**context) -> logging.Logger:
    """Get authentication logger"""
    return get_logger('auth', **context)


def get_email_logger(**context) -> logging.Logger:
    """Get email service logger"""
    return get_logger('email', **context)


def get_api_logger(**context) -> logging.Logger:
    """Get API logger"""
    return get_logger('api', **context)


def get_security_logger(**context) -> logging.Logger:
    """Get security events logger"""
    return get_logger('security', **context)


def get_audit_logger(**context) -> logging.Logger:
    """Get audit logger for compliance"""
    return get_logger('audit', **context)


def log_security_event(event_type: str, action: str, result: str, **context):
    """
    Log a security event for audit purposes

    Args:
        event_type: Type of security event (login, password_reset, etc.)
        action: Specific action taken
        result: Result of the action (success, failure, etc.)
        **context: Additional context (user_id, ip_address, etc.)
    """
    logger = get_security_logger(
        event_type=event_type,
        action=action,
        result=result,
        **context
    )

    message = f"Security Event: {event_type} - {action} - {result}"

    if result.lower() in ['success', 'completed']:
        logger.info(message)
    elif result.lower() in ['failure', 'failed', 'error']:
        logger.warning(message)
    else:
        logger.info(message)


def log_audit_event(action: str, resource: str, result: str, **context):
    """
    Log an audit event for compliance tracking

    Args:
        action: Action performed (create, read, update, delete, etc.)
        resource: Resource affected (user, email, etc.)
        result: Result of the action
        **context: Additional context
    """
    logger = get_audit_logger(
        action=action,
        resource=resource,
        result=result,
        **context
    )

    message = f"Audit: {action} {resource} - {result}"
    logger.info(message)


# Context managers for request-scoped logging
class RequestLoggingContext:
    """Context manager for request-scoped logging with correlation IDs"""

    def __init__(self, correlation_id: str, **context):
        self.correlation_id = correlation_id
        self.context = context
        self.original_loggers = {}

    def __enter__(self):
        # Store references to original loggers if needed
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Cleanup if needed
        pass

    def get_logger(self, name: str) -> logging.Logger:
        """Get logger with request context"""
        return get_logger(name, correlation_id=self.correlation_id, **self.context)