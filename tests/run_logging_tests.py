"""
Complete Logging Security Test Runner
Runs all logging tests and provides analysis
"""
import sys
import os
from datetime import datetime


def main():
    """Run all logging tests"""

    print("🔥 COMPREHENSIVE LOGGING SECURITY TEST SUITE")
    print(f"📅 Started at: {datetime.now()}")
    print("=" * 80)

    # Add the project root to Python path
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    print(f"📂 Project root: {project_root}")
    print(f"🐍 Python path: {sys.path[0]}")

    # Test 1: Configuration Test
    print("\n" + "🔧 CONFIGURATION TESTS".center(80, "="))
    try:
        # Import and run configuration test
        exec(open('logging_config_test.py').read())
        config_success = True
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        config_success = False

    # Test 2: Security Test
    print("\n" + "🛡️ SECURITY TESTS".center(80, "="))
    try:
        # Import and run security test
        exec(open('logging_security_test.py').read())
        security_success = True
    except Exception as e:
        print(f"❌ Security test failed: {e}")
        security_success = False

    # Summary
    print("\n" + "📊 TEST SUMMARY".center(80, "="))
    print(f"Configuration Tests: {'✅ PASSED' if config_success else '❌ FAILED'}")
    print(f"Security Tests: {'✅ PASSED' if security_success else '❌ FAILED'}")

    if config_success and security_success:
        print("\n🎉 ALL TESTS PASSED!")
        print("\n🔍 WHAT TO LOOK FOR IN THE OUTPUT:")
        print("   ✅ Email addresses should show [EMAIL_REDACTED]")
        print("   ✅ Passwords should show [PASSWORD_REDACTED]")
        print("   ✅ Tokens should show [TOKEN_REDACTED]")
        print("   ✅ Credit cards should show [CREDIT_CARD_REDACTED]")
        print("   ✅ SSNs should show [SSN_REDACTED]")
        print("   ✅ Phone numbers should show [PHONE_REDACTED]")
        print("   ✅ Colorful console output (development mode)")
        print("   ✅ Contextual information in log messages")
        print("   ✅ Security and audit events properly formatted")
        print("   ✅ Exception handling with stack traces")

        print("\n⚠️ POTENTIAL SECURITY ISSUES TO WATCH FOR:")
        print("   ❌ Any actual email addresses visible")
        print("   ❌ Any actual passwords visible")
        print("   ❌ Any actual tokens/API keys visible")
        print("   ❌ Credit card numbers or SSNs visible")
        print("   ❌ Error messages that expose system paths")
        print("   ❌ Database connection strings with passwords")

        print("\n🔧 DEVELOPMENT ENVIRONMENT NOTES:")
        print("   • PII redaction is disabled (LOG_PII_REDACTION=false)")
        print("   • This means you WILL see actual emails, passwords, etc.")
        print("   • This is NORMAL for development")
        print("   • In production, PII redaction would be enabled")

    else:
        print("\n❌ SOME TESTS FAILED!")
        print("   Check the error messages above for details")
        print("   You may need to:")
        print("   • Install missing dependencies")
        print("   • Fix import paths")
        print("   • Update your .env file")
        print("   • Create the backend/utils files")

    print("\n" + "=" * 80)
    return config_success and security_success


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)