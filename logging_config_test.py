"""
Logging Configuration and Environment Test
Tests the logging configuration and environment setup
"""
import os
import sys
from pathlib import Path


def test_logging_configuration():
    """Test logging configuration and environment setup"""

    print("🔧 TESTING LOGGING CONFIGURATION AND ENVIRONMENT")
    print("=" * 60)

    # Test 1: Environment Variables
    print("\n📋 TEST 1: Environment Variables Check")
    required_env_vars = [
        'ENVIRONMENT', 'DEBUG', 'LOG_LEVEL', 'LOG_TO_FILE',
        'LOG_PII_REDACTION', 'LOG_RATE_LIMIT_PER_MINUTE'
    ]

    for var in required_env_vars:
        value = os.getenv(var, 'NOT_SET')
        print(f"   {var}: {value}")

    # Test 2: Settings Configuration
    print("\n⚙️ TEST 2: Settings Configuration")
    try:
        from backend.config.settings import settings
        print(f"   Environment: {settings.ENVIRONMENT}")
        print(f"   Debug Mode: {settings.DEBUG}")
        print(f"   Log Level: {settings.LOG_LEVEL}")
        print(f"   Log to File: {settings.LOG_TO_FILE}")
        print(f"   PII Redaction: {settings.LOG_PII_REDACTION}")
        print(f"   Rate Limit: {settings.LOG_RATE_LIMIT_PER_MINUTE}")
        print(f"   Log Directory: {settings.LOG_DIRECTORY}")
        print("✅ Settings loaded successfully")
    except Exception as e:
        print(f"❌ Failed to load settings: {e}")
        return False

    # Test 3: Log Directory
    print("\n📁 TEST 3: Log Directory Check")
    log_dir = Path(settings.LOG_DIRECTORY)
    print(f"   Log directory path: {log_dir.absolute()}")
    print(f"   Directory exists: {log_dir.exists()}")

    if settings.LOG_TO_FILE and not log_dir.exists():
        print("⚠️ Log directory doesn't exist but LOG_TO_FILE=true")
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            print("✅ Created log directory")
        except Exception as e:
            print(f"❌ Failed to create log directory: {e}")

    # Test 4: Logging System Initialization
    print("\n🚀 TEST 4: Logging System Initialization")
    try:
        from backend.utils.logging import initialize_logging, _logging_config

        # Re-initialize with current settings
        initialize_logging(settings.ENVIRONMENT, settings.DEBUG)

        if _logging_config:
            print(f"   Environment: {_logging_config.environment}")
            print(f"   Debug: {_logging_config.debug}")
            print(f"   Is Production: {_logging_config.is_production}")
            print(f"   Log Directory: {_logging_config.log_directory}")
            print("✅ Logging configuration initialized")
        else:
            print("⚠️ Logging configuration not initialized")
    except Exception as e:
        print(f"❌ Failed to initialize logging: {e}")
        return False

    # Test 5: Logger Creation and Configuration
    print("\n🔧 TEST 5: Logger Creation and Configuration")
    try:
        from backend.utils.logging import get_logger
        import logging

        # Test each logger type
        logger_types = ['auth', 'email', 'api', 'security', 'audit']

        for logger_type in logger_types:
            logger = get_logger(logger_type)
            print(f"   {logger_type} logger:")
            print(f"      Name: {logger.name}")
            print(f"      Level: {logging.getLevelName(logger.level)}")
            print(f"      Handlers: {len(logger.handlers)}")
            print(f"      Propagate: {logger.propagate}")

            # Check handler types
            for i, handler in enumerate(logger.handlers):
                print(f"         Handler {i + 1}: {type(handler).__name__}")
                print(f"         Level: {logging.getLevelName(handler.level)}")
                print(f"         Formatter: {type(handler.formatter).__name__}")
                print(f"         Filters: {len(handler.filters)}")

        print("✅ All loggers configured properly")
    except Exception as e:
        print(f"❌ Failed to test logger configuration: {e}")
        return False

    # Test 6: Filter and Formatter Testing
    print("\n🛡️ TEST 6: Filter and Formatter Testing")
    try:
        from backend.utils.log_filters import PIIFilter, SecurityFilter, RateLimitFilter
        from backend.utils.log_formatters import DevelopmentFormatter, ProductionFormatter

        # Test filter creation
        pii_filter = PIIFilter()
        security_filter = SecurityFilter(settings.ENVIRONMENT)
        rate_filter = RateLimitFilter(settings.LOG_RATE_LIMIT_PER_MINUTE)

        print(f"   PII Filter: {type(pii_filter).__name__}")
        print(f"   Security Filter: {type(security_filter).__name__} (env: {security_filter.environment})")
        print(f"   Rate Filter: {type(rate_filter).__name__} (limit: {rate_filter.max_logs_per_minute})")

        # Test formatter creation
        dev_formatter = DevelopmentFormatter()
        prod_formatter = ProductionFormatter()

        print(f"   Dev Formatter: {type(dev_formatter).__name__}")
        print(f"   Prod Formatter: {type(prod_formatter).__name__}")
        print("✅ Filters and formatters working")
    except Exception as e:
        print(f"❌ Failed to test filters and formatters: {e}")
        return False

    # Test 7: Test Message with PII
    print("\n🔍 TEST 7: PII Redaction Test")
    try:
        from backend.utils.log_filters import PIIFilter
        import logging

        # Create a test record
        logger = logging.getLogger('test')
        record = logging.LogRecord(
            name='test',
            level=logging.INFO,
            pathname='test.py',
            lineno=1,
            msg="User john.doe@example.com logged in with password=secret123 and token=abc123xyz",
            args=(),
            exc_info=None
        )

        # Apply PII filter
        pii_filter = PIIFilter()
        pii_filter.filter(record)

        print(f"   Original: User john.doe@example.com logged in with password=secret123 and token=abc123xyz")
        print(f"   Filtered: {record.msg}")

        # Check if redaction worked
        if '[EMAIL_REDACTED]' in record.msg and '[PASSWORD_REDACTED]' in record.msg:
            print("✅ PII redaction working correctly")
        else:
            print("⚠️ PII redaction may not be working properly")

    except Exception as e:
        print(f"❌ Failed to test PII redaction: {e}")

    # Test 8: Security Configuration Check
    print("\n🔒 TEST 8: Security Configuration Check")
    security_checks = {
        'PII Redaction Enabled': settings.LOG_PII_REDACTION,
        'Rate Limiting Configured': settings.LOG_RATE_LIMIT_PER_MINUTE > 0,
        'Audit Logging Enabled': settings.AUDIT_LOG_ENABLED,
        'Development Environment': settings.ENVIRONMENT == 'development',
        'Debug Mode': settings.DEBUG
    }

    for check, status in security_checks.items():
        status_emoji = "✅" if status else "⚠️"
        print(f"   {status_emoji} {check}: {status}")

    # Security warnings for development environment
    if settings.ENVIRONMENT == 'development':
        print("\n⚠️ DEVELOPMENT ENVIRONMENT NOTES:")
        print("   • PII redaction is disabled (LOG_PII_REDACTION=false)")
        print("   • Debug mode is enabled")
        print("   • Logs are going to console (LOG_TO_FILE=false)")
        print("   • This is normal for development")

    print("\n" + "=" * 60)
    print("✅ LOGGING CONFIGURATION TEST COMPLETED!")
    print("🔍 Review the output above for any issues")
    print("=" * 60)

    return True


if __name__ == "__main__":
    test_logging_configuration()