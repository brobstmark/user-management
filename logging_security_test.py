"""
Comprehensive Logging Security Test Suite
Tests all aspects of the secure logging system
"""
import time
import json
from datetime import datetime


# Test the logging system
def test_logging_system():
    """Run comprehensive tests of the logging system"""

    print("🔥 STARTING COMPREHENSIVE LOGGING SECURITY TESTS")
    print("=" * 60)

    try:
        # Import the logging system
        from backend.utils.logging import (
            get_auth_logger, get_email_logger, get_api_logger,
            get_security_logger, get_audit_logger, log_security_event,
            log_audit_event, initialize_logging
        )
        print("✅ Logging system imports successful")
    except ImportError as e:
        print(f"❌ Failed to import logging system: {e}")
        return False

    # Test 1: Basic Logger Creation
    print("\n📝 TEST 1: Basic Logger Creation")
    try:
        auth_logger = get_auth_logger()
        email_logger = get_email_logger()
        api_logger = get_api_logger()
        security_logger = get_security_logger()
        audit_logger = get_audit_logger()
        print("✅ All loggers created successfully")
    except Exception as e:
        print(f"❌ Failed to create loggers: {e}")
        return False

    # Test 2: PII Redaction Testing
    print("\n🔒 TEST 2: PII Redaction Testing")
    test_messages = [
        "User registered with email john.doe@example.com",
        "Password reset token: abc123xyz789 for user test@company.com",
        "JWT token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "Credit card number: 4532-1234-5678-9012 was processed",
        "SSN: 123-45-6789 verification failed",
        "Phone number: 555-123-4567 contact attempt",
        "User password=secretPassword123 was changed",
        "API key=sk_live_123456789abcdef for merchant",
        "Database connection: postgresql://user:mypassword@localhost:5432/db"
    ]

    for msg in test_messages:
        auth_logger.info(msg)
        print(f"   📤 Sent: {msg[:50]}...")

    # Test 3: Different Log Levels
    print("\n📊 TEST 3: Different Log Levels")
    auth_logger.debug("Debug level message with email admin@test.com")
    auth_logger.info("Info level message with token abc123def456")
    auth_logger.warning("Warning level message with password=hidden123")
    auth_logger.error("Error level message with user john@example.com")
    auth_logger.critical("Critical level message with sensitive data")
    print("✅ All log levels tested")

    # Test 4: Contextual Logging
    print("\n🎯 TEST 4: Contextual Logging")
    contextual_logger = get_auth_logger(
        user_id=12345,
        session_id="sess_abc123",
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0 Test Browser"
    )
    contextual_logger.info("Login attempt with context")
    contextual_logger.warning("Failed login attempt with context")
    print("✅ Contextual logging tested")

    # Test 5: Security Event Logging
    print("\n🛡️ TEST 5: Security Event Logging")
    log_security_event(
        event_type="authentication",
        action="login",
        result="success",
        user_id=123,
        ip_address="192.168.1.100"
    )
    log_security_event(
        event_type="authentication",
        action="login",
        result="failure",
        user_id=None,
        attempted_email="hacker@evil.com",
        ip_address="10.0.0.1"
    )
    log_security_event(
        event_type="password_reset",
        action="request",
        result="success",
        user_id=456,
        email="user@example.com"
    )
    print("✅ Security event logging tested")

    # Test 6: Audit Event Logging
    print("\n📋 TEST 6: Audit Event Logging")
    log_audit_event(
        action="create",
        resource="user",
        result="success",
        user_id=789,
        admin_id=1,
        details="New user registration"
    )
    log_audit_event(
        action="update",
        resource="user_profile",
        result="success",
        user_id=123,
        changed_fields=["email", "phone"],
        old_email="old@example.com",
        new_email="new@example.com"
    )
    print("✅ Audit event logging tested")

    # Test 7: Exception Handling
    print("\n⚠️ TEST 7: Exception Handling")
    try:
        # Simulate an error
        result = 1 / 0
    except Exception as e:
        auth_logger.error("Division by zero error occurred", exc_info=True, extra={
            'user_id': 123,
            'operation': 'calculate',
            'sensitive_data': 'password123'
        })
    print("✅ Exception logging tested")

    # Test 8: Email Service Logging
    print("\n📧 TEST 8: Email Service Logging")
    email_logger.info("Sending verification email to user@example.com")
    email_logger.info("Email sent successfully", extra={
        'recipient': 'user@example.com',
        'template': 'verification',
        'message_id': 'msg_123abc'
    })
    email_logger.error("Failed to send email", extra={
        'recipient': 'invalid@email.com',
        'error_code': 'SMTP_550',
        'smtp_password': 'secret123'  # This should be redacted
    })
    print("✅ Email service logging tested")

    # Test 9: API Request Logging
    print("\n🌐 TEST 9: API Request Logging")
    api_logger.info("POST /api/v1/auth/login", extra={
        'method': 'POST',
        'endpoint': '/api/v1/auth/login',
        'status_code': 200,
        'user_agent': 'Mozilla/5.0',
        'ip_address': '192.168.1.100',
        'request_body': {
            'email': 'user@example.com',
            'password': 'userpassword123'  # Should be redacted
        }
    })
    api_logger.info("GET /api/v1/users/me", extra={
        'method': 'GET',
        'endpoint': '/api/v1/users/me',
        'status_code': 200,
        'user_id': 123,
        'auth_token': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'  # Should be redacted
    })
    print("✅ API request logging tested")

    # Test 10: Rate Limiting Test (commented out to avoid flooding)
    print("\n⏱️ TEST 10: Rate Limiting Test (Limited)")
    print("   (Testing 5 rapid messages instead of full rate limit)")
    for i in range(5):
        auth_logger.info(f"Rapid message {i + 1} with email test{i}@example.com")
        time.sleep(0.1)  # Small delay
    print("✅ Rate limiting test completed")

    # Test 11: Multiple Logger Types
    print("\n🔄 TEST 11: Multiple Logger Types")
    loggers = {
        'auth': get_auth_logger(),
        'email': get_email_logger(),
        'api': get_api_logger(),
        'security': get_security_logger(),
        'audit': get_audit_logger()
    }

    for logger_name, logger in loggers.items():
        logger.info(f"Test message from {logger_name} logger with email test@{logger_name}.com")
    print("✅ Multiple logger types tested")

    # Test 12: JSON Serialization Edge Cases
    print("\n🔧 TEST 12: JSON Serialization Edge Cases")
    try:
        # Test with non-serializable data
        class NonSerializable:
            def __str__(self):
                return "NonSerializable object"

        api_logger.info("Testing complex data", extra={
            'datetime_obj': datetime.now(),
            'non_serializable': NonSerializable(),
            'nested_dict': {
                'user_email': 'nested@example.com',
                'user_password': 'nested_secret123',
                'deep_nest': {
                    'token': 'abc123xyz789'
                }
            }
        })
        print("✅ JSON serialization edge cases tested")
    except Exception as e:
        print(f"⚠️ JSON serialization issue: {e}")

    print("\n" + "=" * 60)
    print("🎉 ALL LOGGING TESTS COMPLETED!")
    print("📊 Check console output above for:")
    print("   • PII redaction (emails should show [EMAIL_REDACTED])")
    print("   • Token redaction (tokens should show [TOKEN_REDACTED])")
    print("   • Password redaction (passwords should show [PASSWORD_REDACTED])")
    print("   • Proper log formatting for development environment")
    print("   • Error handling and exception logging")
    print("   • Security and audit event formatting")
    print("=" * 60)

    return True


if __name__ == "__main__":
    test_logging_system()