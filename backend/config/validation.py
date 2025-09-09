"""
Configuration Validation
Validates application settings and logs results
"""
from backend.config.settings import settings
from backend.utils.logging import get_security_logger


def validate_configuration():
    """Validate critical configuration and log results"""
    validation_logger = get_security_logger()

    issues = []

    # Validate email configuration
    if not settings.EMAIL_USERNAME:
        issues.append("Email not configured - email features disabled")

    # Validate security settings
    if settings.SECRET_KEY == "your-super-secret-key-change-this":
        issues.append("Default secret key detected - security risk")

    # Validate environment
    if settings.ENVIRONMENT == "production" and settings.DEBUG:
        issues.append("Debug mode enabled in production - security risk")

    # Log validation results
    if issues:
        for issue in issues:
            validation_logger.warning(
                f"Configuration issue: {issue}",
                extra={'event_type': 'configuration_validation'}
            )
    else:
        validation_logger.info(
            "Configuration validation passed",
            extra={'event_type': 'configuration_validation'}
        )

    return issues  # Return issues so caller can decide what to do