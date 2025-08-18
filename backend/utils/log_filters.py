"""
PII Sanitization and Security Filters for Logging
Automatically redacts sensitive information from log messages
"""
import re
import logging
from typing import Any, Dict, List


class PIIFilter(logging.Filter):
    """
    Filter to automatically redact Personally Identifiable Information (PII)
    and sensitive data from log messages
    """

    def __init__(self):
        super().__init__()

        # Email pattern - matches email addresses
        self.email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )

        # Token patterns - matches various token formats
        self.token_patterns = [
            re.compile(r'\b[A-Za-z0-9+/]{20,}={0,2}\b'),  # Base64-like tokens
            re.compile(r'\b[A-Fa-f0-9]{32,}\b'),  # Hex tokens (32+ chars)
            re.compile(r'\bBearereyJ[A-Za-z0-9+/=]+\b'),  # JWT tokens
            re.compile(r'\btoken[=:]\s*[A-Za-z0-9+/=]+', re.IGNORECASE),  # token=value
        ]

        # Password patterns
        self.password_patterns = [
            re.compile(r'\bpassword[=:]\s*\S+', re.IGNORECASE),
            re.compile(r'\bpwd[=:]\s*\S+', re.IGNORECASE),
            re.compile(r'\bpass[=:]\s*\S+', re.IGNORECASE),
        ]

        # Credit card pattern (basic)
        self.credit_card_pattern = re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b')

        # SSN pattern (US Social Security Numbers)
        self.ssn_pattern = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')

        # Phone number patterns
        self.phone_patterns = [
            re.compile(r'\b\d{3}-\d{3}-\d{4}\b'),  # 123-456-7890
            re.compile(r'\b\(\d{3}\)\s?\d{3}-\d{4}\b'),  # (123) 456-7890
        ]

        # IP address pattern (optional - might be needed for debugging)
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filter and sanitize the log record

        Args:
            record: The log record to filter

        Returns:
            bool: Always True (we modify in place rather than filter out)
        """
        # Sanitize the main message
        if hasattr(record, 'getMessage'):
            original_msg = record.getMessage()
            record.msg = self._sanitize_message(original_msg)
            record.args = ()  # Clear args since we've formatted the message

        # Sanitize any additional attributes that might contain sensitive data
        if hasattr(record, 'extra_data'):
            record.extra_data = self._sanitize_dict(record.extra_data)

        return True

    def _sanitize_message(self, message: str) -> str:
        """
        Sanitize a message string by redacting PII and sensitive data

        Args:
            message: Original message string

        Returns:
            str: Sanitized message with PII redacted
        """
        sanitized = message

        # Redact emails
        sanitized = self.email_pattern.sub('[EMAIL_REDACTED]', sanitized)

        # Redact tokens
        for pattern in self.token_patterns:
            sanitized = pattern.sub('[TOKEN_REDACTED]', sanitized)

        # Redact passwords
        for pattern in self.password_patterns:
            sanitized = pattern.sub(lambda m: m.group().split('=')[0] + '=[PASSWORD_REDACTED]', sanitized)

        # Redact credit cards
        sanitized = self.credit_card_pattern.sub('[CREDIT_CARD_REDACTED]', sanitized)

        # Redact SSNs
        sanitized = self.ssn_pattern.sub('[SSN_REDACTED]', sanitized)

        # Redact phone numbers
        for pattern in self.phone_patterns:
            sanitized = pattern.sub('[PHONE_REDACTED]', sanitized)

        return sanitized

    def _sanitize_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively sanitize dictionary data

        Args:
            data: Dictionary to sanitize

        Returns:
            Dict: Sanitized dictionary
        """
        if not isinstance(data, dict):
            return data

        sanitized = {}
        sensitive_keys = {
            'password', 'pwd', 'pass', 'token', 'key', 'secret',
            'email', 'username', 'user_email', 'credit_card',
            'ssn', 'social_security', 'phone'
        }

        for key, value in data.items():
            key_lower = key.lower()

            if any(sensitive in key_lower for sensitive in sensitive_keys):
                sanitized[key] = '[REDACTED]'
            elif isinstance(value, str):
                sanitized[key] = self._sanitize_message(value)
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_dict(value)
            elif isinstance(value, list):
                sanitized[key] = [self._sanitize_dict(item) if isinstance(item, dict)
                                  else self._sanitize_message(str(item)) if isinstance(item, str)
                else item for item in value]
            else:
                sanitized[key] = value

        return sanitized


class SecurityFilter(logging.Filter):
    """
    Security-focused filter to redact sensitive information from stack traces
    and error messages in production
    """

    def __init__(self, environment: str = "production"):
        super().__init__()
        self.environment = environment
        self.is_production = environment == "production"

        # Sensitive path patterns to redact
        self.sensitive_paths = [
            re.compile(r'/home/[^/]+'),  # User home directories
            re.compile(r'/var/[^/]+'),  # System directories
            re.compile(r'C:\\Users\\[^\\]+'),  # Windows user directories
        ]

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filter sensitive information from error messages and stack traces
        """
        # In production, sanitize stack traces and file paths
        if self.is_production and hasattr(record, 'exc_text') and record.exc_text:
            record.exc_text = self._sanitize_stack_trace(record.exc_text)

        # Sanitize file paths in all environments
        if hasattr(record, 'pathname'):
            record.pathname = self._sanitize_path(record.pathname)

        return True

    def _sanitize_stack_trace(self, exc_text: str) -> str:
        """
        Sanitize stack traces by removing sensitive file paths
        """
        sanitized = exc_text

        # Replace sensitive paths
        for pattern in self.sensitive_paths:
            sanitized = pattern.sub('[PATH_REDACTED]', sanitized)

        return sanitized

    def _sanitize_path(self, path: str) -> str:
        """
        Sanitize file paths to remove sensitive directory information
        """
        # Keep only the filename and immediate parent directory
        parts = path.split('/')
        if len(parts) > 2:
            return f".../{'/'.join(parts[-2:])}"
        return path


class RateLimitFilter(logging.Filter):
    """
    Rate limiting filter to prevent log flooding attacks
    """

    def __init__(self, max_logs_per_minute: int = 100):
        super().__init__()
        self.max_logs_per_minute = max_logs_per_minute
        self.log_counts = {}
        self.last_reset = 0

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Rate limit log messages to prevent flooding
        """
        import time

        current_time = int(time.time() / 60)  # Current minute

        # Reset counters every minute
        if current_time != self.last_reset:
            self.log_counts.clear()
            self.last_reset = current_time

        # Count logs by logger name and level
        key = f"{record.name}:{record.levelname}"
        self.log_counts[key] = self.log_counts.get(key, 0) + 1

        # Allow log if under rate limit
        if self.log_counts[key] <= self.max_logs_per_minute:
            return True

        # On first rate limit hit, log a warning
        if self.log_counts[key] == self.max_logs_per_minute + 1:
            record.msg = f"Rate limit reached for {key} - suppressing further logs this minute"
            return True

        # Suppress subsequent logs
        return False


# Convenience function to create all filters
def create_security_filters(environment: str = "production") -> List[logging.Filter]:
    """
    Create a list of all security filters

    Args:
        environment: Current environment (development, staging, production)

    Returns:
        List of configured logging filters
    """
    filters = [
        PIIFilter(),
        SecurityFilter(environment),
    ]

    # Add rate limiting in production
    if environment == "production":
        filters.append(RateLimitFilter(max_logs_per_minute=200))

    return filters