import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from jinja2 import Template
from backend.config.settings import settings
import json
import os
from datetime import datetime
from typing import Optional

# 🔥 Import secure logging system
from backend.utils.logging import get_email_logger, log_security_event, log_audit_event


class EmailService:
    def __init__(self):
        # Initialize secure logger for email service
        self.logger = get_email_logger()

        # SMTP Configuration
        self.smtp_server = settings.EMAIL_HOST
        self.smtp_port = settings.EMAIL_PORT
        self.username = settings.EMAIL_USERNAME
        self.password = settings.EMAIL_PASSWORD
        self.from_email = settings.EMAIL_FROM
        self.from_name = settings.EMAIL_FROM_NAME
        self.use_tls = settings.EMAIL_USE_TLS

        # Keep file fallback for development/testing
        self.fallback_to_file = getattr(settings, 'EMAIL_FALLBACK_TO_FILE', False)

        # Dynamic URL configuration
        self.frontend_url = settings.FRONTEND_URL
        self.api_url = settings.API_URL
        self.environment = settings.ENVIRONMENT

        # Log initialization (PII automatically redacted)
        self.logger.info("Email service initialized", extra={
            'environment': self.environment,
            'smtp_server': self.smtp_server,
            'smtp_port': self.smtp_port,
            'use_tls': self.use_tls,
            'fallback_enabled': self.fallback_to_file,
            'frontend_url': self.frontend_url,
            'api_url': self.api_url
        })

    def send_email(
            self,
            to_email: str,
            subject: str,
            html_content: str,
            text_content: Optional[str] = None
    ) -> bool:
        """Send email via SMTP with fallback to file storage"""

        # Log email attempt (email will be automatically redacted)
        self.logger.info("Initiating email send", extra={
            'recipient': to_email,  # Will be redacted to [EMAIL_REDACTED]
            'subject': subject,
            'method': 'file_fallback' if self.fallback_to_file else 'smtp',
            'environment': self.environment
        })

        # If fallback is enabled, save to file instead
        if self.fallback_to_file:
            self.logger.debug("Using file fallback method")
            return self._save_email_to_file(to_email, subject, html_content, text_content)

        try:
            # Create message
            message = MIMEMultipart("alternative")
            message["Subject"] = subject
            message["From"] = f"{self.from_name} <{self.from_email}>"
            message["To"] = to_email

            # Add text content if provided
            if text_content:
                text_part = MIMEText(text_content, "plain")
                message.attach(text_part)
                self.logger.debug("Added text content to email")

            # Add HTML content
            html_part = MIMEText(html_content, "html")
            message.attach(html_part)
            self.logger.debug("Added HTML content to email")

            # Create secure connection and send
            context = ssl.create_default_context()

            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                self.logger.debug("Establishing SMTP connection")
                server.starttls(context=context)  # Enable security
                self.logger.debug("TLS encryption enabled")

                server.login(self.username, self.password)
                self.logger.debug("SMTP authentication successful")

                server.sendmail(self.from_email, to_email, message.as_string())

            # Log successful send (email redacted automatically)
            self.logger.info("Email sent successfully via SMTP", extra={
                'recipient': to_email,  # Will be redacted
                'method': 'smtp',
                'environment': self.environment
            })

            # Log security event for audit trail
            log_security_event(
                event_type="email",
                action="send_email",
                result="success",
                method="smtp",
                environment=self.environment
            )

            return True

        except Exception as e:
            # Log SMTP failure (don't include full exception in production)
            self.logger.warning("SMTP email send failed, attempting fallback", extra={
                'recipient': to_email,  # Will be redacted
                'error_type': type(e).__name__,
                'smtp_server': self.smtp_server,
                'smtp_port': self.smtp_port
            })

            # Log security event for failed email
            log_security_event(
                event_type="email",
                action="send_email",
                result="smtp_failure",
                error_type=type(e).__name__
            )

            # Fallback to file storage if SMTP fails
            self.logger.info("Attempting file fallback after SMTP failure")
            fallback_success = self._save_email_to_file(to_email, subject, html_content, text_content)

            if not fallback_success:
                # Complete failure - this is serious
                self.logger.error("Complete email delivery failure", extra={
                    'recipient': to_email,  # Will be redacted
                    'smtp_error': type(e).__name__,
                    'fallback_failed': True
                })

                log_security_event(
                    event_type="email",
                    action="send_email",
                    result="complete_failure",
                    error_type=type(e).__name__
                )

            return fallback_success

    def _save_email_to_file(
            self,
            to_email: str,
            subject: str,
            html_content: str,
            text_content: Optional[str] = None
    ) -> bool:
        """Fallback method: save email to file for development"""
        try:
            # Create dev_emails directory if it doesn't exist
            os.makedirs("dev_emails", exist_ok=True)
            self.logger.debug("Created dev_emails directory")

            # Create email data
            email_data = {
                "to": to_email,
                "subject": subject,
                "html_content": html_content,
                "text_content": text_content,
                "timestamp": datetime.now().isoformat(),
                "method": "file_fallback",
                "environment": self.environment,
                "frontend_url": self.frontend_url,
                "api_url": self.api_url
            }

            # Save to file with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"dev_emails/email_{timestamp}_{to_email.replace('@', '_at_')}.json"

            with open(filename, 'w') as f:
                json.dump(email_data, f, indent=2)

            self.logger.info("Email saved to file successfully", extra={
                'recipient': to_email,  # Will be redacted
                'filename': filename,
                'method': 'file_fallback'
            })

            # Log audit event for file storage
            log_audit_event(
                action="email_file_save",
                resource="email",
                result="success",
                filename=filename
            )

            return True

        except Exception as e:
            self.logger.error("Failed to save email to file", extra={
                'recipient': to_email,  # Will be redacted
                'error_type': type(e).__name__,
                'error_message': str(e)
            })

            log_security_event(
                event_type="email",
                action="file_fallback",
                result="failure",
                error_type=type(e).__name__
            )

            return False

    async def send_verification_email(self, user_email: str, user_name: str, verification_token: str) -> bool:
        """Send email verification email with dynamic URLs"""

        self.logger.info("Sending verification email", extra={
            'email_type': 'verification',
            'recipient': user_email,  # Will be redacted
            'user_name': user_name
        })

        # Use dynamic API URL for verification endpoint
        verification_url = f"{self.api_url}/api/v1/auth/verify-email?token={verification_token}"

        self.logger.debug("Generated verification URL", extra={
            'url_type': 'verification',
            'api_url': self.api_url
        })

        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Verify Your Email</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; background-color: #f4f4f4; }
                .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
                .header { text-align: center; margin-bottom: 30px; }
                .header h1 { color: #333; margin-bottom: 10px; }
                .content { margin-bottom: 30px; }
                .button { display: inline-block; background-color: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; }
                .button:hover { background-color: #0056b3; }
                .footer { text-align: center; color: #666; font-size: 14px; border-top: 1px solid #eee; padding-top: 20px; margin-top: 30px; }
                .url-fallback { word-break: break-all; background-color: #f8f9fa; padding: 10px; border-radius: 5px; margin-top: 15px; }
                .env-info { background-color: #e7f3ff; border: 1px solid #b8daff; color: #004085; padding: 10px; border-radius: 5px; margin: 15px 0; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🎉 Welcome to User Management System!</h1>
                    <p>Please verify your email address to activate your account</p>
                </div>

                <div class="content">
                    <p>Hi {{ user_name }}!</p>
                    <p>Thanks for signing up! Please click the button below to verify your email address and activate your account:</p>

                    <p style="text-align: center; margin: 30px 0;">
                        <a href="{{ verification_url }}" class="button">Verify Email Address</a>
                    </p>

                    <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
                    <div class="url-fallback">{{ verification_url }}</div>

                    <p><strong>Important:</strong> This verification link will expire in 24 hours for security reasons.</p>

                    {% if environment == 'development' %}
                    <div class="env-info">
                        <strong>🔧 Development Mode:</strong> Environment: {{ environment }} | Frontend: {{ frontend_url }} | API: {{ api_url }}
                    </div>
                    {% endif %}
                </div>

                <div class="footer">
                    <p>If you didn't create an account, you can safely ignore this email.</p>
                    <p>This is an automated message, please do not reply.</p>
                </div>
            </div>
        </body>
        </html>
        """

        # Render template with dynamic values
        template = Template(html_template)
        html_content = template.render(
            verification_url=verification_url,
            user_name=user_name,
            environment=self.environment,
            frontend_url=self.frontend_url,
            api_url=self.api_url
        )

        # Send email
        success = self.send_email(
            to_email=user_email,
            subject="Verify Your Email Address - User Management System",
            html_content=html_content,
            text_content=f"Please verify your email by visiting: {verification_url}"
        )

        # Log the result
        if success:
            self.logger.info("Verification email sent successfully", extra={
                'email_type': 'verification',
                'recipient': user_email  # Will be redacted
            })

            log_audit_event(
                action="send_verification_email",
                resource="user_account",
                result="success",
                recipient_email=user_email  # Will be redacted by audit logger
            )
        else:
            self.logger.error("Verification email send failed", extra={
                'email_type': 'verification',
                'recipient': user_email  # Will be redacted
            })

        return success

    async def send_password_reset_email(self, user_email: str, user_name: str, reset_token: str) -> bool:
        """Send password reset email with dynamic URLs"""

        self.logger.info("Sending password reset email", extra={
            'email_type': 'password_reset',
            'recipient': user_email,  # Will be redacted
            'user_name': user_name
        })

        # Use dynamic frontend URL for reset page
        reset_url = f"{self.frontend_url}/frontend/reset-password.html?token={reset_token}"
        login_url = f"{self.frontend_url}/frontend/pages/auth/login.html"

        self.logger.debug("Generated password reset URLs", extra={
            'url_type': 'password_reset',
            'frontend_url': self.frontend_url
        })

        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Reset Your Password</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; background-color: #f4f4f4; }
                .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
                .header { text-align: center; margin-bottom: 30px; }
                .header h1 { color: #333; margin-bottom: 10px; }
                .content { margin-bottom: 30px; }
                .button { display: inline-block; background-color: #dc3545; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; }
                .button:hover { background-color: #c82333; }
                .footer { text-align: center; color: #666; font-size: 14px; border-top: 1px solid #eee; padding-top: 20px; margin-top: 30px; }
                .url-fallback { word-break: break-all; background-color: #f8f9fa; padding: 10px; border-radius: 5px; margin-top: 15px; }
                .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 15px; border-radius: 5px; margin: 20px 0; }
                .env-info { background-color: #e7f3ff; border: 1px solid #b8daff; color: #004085; padding: 10px; border-radius: 5px; margin: 15px 0; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔒 Password Reset Request</h1>
                    <p>Someone requested a password reset for your account</p>
                </div>

                <div class="content">
                    <p>Hi {{ user_name }}!</p>
                    <p>We received a request to reset the password for your account. If you made this request, click the button below to reset your password:</p>

                    <p style="text-align: center; margin: 30px 0;">
                        <a href="{{ reset_url }}" class="button">Reset Password</a>
                    </p>

                    <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
                    <div class="url-fallback">{{ reset_url }}</div>

                    <div class="warning">
                        <strong>⚠️ Important Security Information:</strong>
                        <ul>
                            <li>This link will expire in 1 hour for security reasons</li>
                            <li>If you didn't request this password reset, you can safely ignore this email</li>
                            <li>Your password will remain unchanged until you access the link above</li>
                        </ul>
                    </div>

                    {% if environment == 'development' %}
                    <div class="env-info">
                        <strong>🔧 Development Mode:</strong> Environment: {{ environment }} | Frontend: {{ frontend_url }} | API: {{ api_url }}
                    </div>
                    {% endif %}
                </div>

                <div class="footer">
                    <p>If you didn't request a password reset, someone may be trying to access your account. Consider changing your password if you're concerned.</p>
                    <p>This is an automated message, please do not reply.</p>
                </div>
            </div>
        </body>
        </html>
        """

        # Render template with dynamic values
        template = Template(html_template)
        html_content = template.render(
            reset_url=reset_url,
            user_name=user_name,
            environment=self.environment,
            frontend_url=self.frontend_url,
            api_url=self.api_url
        )

        # Send email
        success = self.send_email(
            to_email=user_email,
            subject="🔒 Password Reset Request - User Management System",
            html_content=html_content,
            text_content=f"Password reset requested. Visit: {reset_url} (expires in 1 hour)"
        )

        # Log the result with security context
        if success:
            self.logger.info("Password reset email sent successfully", extra={
                'email_type': 'password_reset',
                'recipient': user_email  # Will be redacted
            })

            log_security_event(
                event_type="password_reset",
                action="send_reset_email",
                result="success",
                recipient_email=user_email  # Will be redacted
            )
        else:
            self.logger.error("Password reset email send failed", extra={
                'email_type': 'password_reset',
                'recipient': user_email  # Will be redacted
            })

            log_security_event(
                event_type="password_reset",
                action="send_reset_email",
                result="failure",
                recipient_email=user_email  # Will be redacted
            )

        return success

    async def send_username_recovery_email(self, user_email: str, user_name: str, username: str) -> bool:
        """Send username recovery email with dynamic URLs"""

        self.logger.info("Sending username recovery email", extra={
            'email_type': 'username_recovery',
            'recipient': user_email,  # Will be redacted
            'user_name': user_name
        })

        # Use dynamic frontend URL for login page
        login_url = f"{self.frontend_url}/frontend/pages/auth/login.html"

        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Your Username Recovery</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; background-color: #f4f4f4; }
                .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
                .header { text-align: center; margin-bottom: 30px; }
                .header h1 { color: #333; margin-bottom: 10px; }
                .content { margin-bottom: 30px; }
                .username-box { background-color: #e7f3ff; border: 2px solid #007bff; padding: 20px; text-align: center; border-radius: 10px; margin: 20px 0; }
                .username-box .username { font-size: 24px; font-weight: bold; color: #007bff; }
                .footer { text-align: center; color: #666; font-size: 14px; border-top: 1px solid #eee; padding-top: 20px; margin-top: 30px; }
                .button { display: inline-block; background-color: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; }
                .button:hover { background-color: #0056b3; }
                .env-info { background-color: #e7f3ff; border: 1px solid #b8daff; color: #004085; padding: 10px; border-radius: 5px; margin: 15px 0; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>👤 Username Recovery</h1>
                    <p>Here's the username for your account</p>
                </div>

                <div class="content">
                    <p>Hi {{ user_name }}!</p>
                    <p>You requested to recover your username. Here's the username associated with this email address:</p>

                    <div class="username-box">
                        <div style="margin-bottom: 10px;">Your Username:</div>
                        <div class="username">{{ username }}</div>
                    </div>

                    <p>You can now use this username to log in to your account. If you've also forgotten your password, you can request a password reset.</p>

                    <p style="text-align: center; margin: 30px 0;">
                        <a href="{{ login_url }}" class="button">Go to Login</a>
                    </p>

                    {% if environment == 'development' %}
                    <div class="env-info">
                        <strong>🔧 Development Mode:</strong> Environment: {{ environment }} | Frontend: {{ frontend_url }} | API: {{ api_url }}
                    </div>
                    {% endif %}
                </div>

                <div class="footer">
                    <p>If you didn't request this username recovery, you can safely ignore this email.</p>
                    <p>This is an automated message, please do not reply.</p>
                </div>
            </div>
        </body>
        </html>
        """

        # Render template with dynamic values
        template = Template(html_template)
        html_content = template.render(
            user_name=user_name,
            username=username or "Not set",
            login_url=login_url,
            environment=self.environment,
            frontend_url=self.frontend_url,
            api_url=self.api_url
        )

        # Send email
        success = self.send_email(
            to_email=user_email,
            subject="👤 Username Recovery - User Management System",
            html_content=html_content,
            text_content=f"Your username is: {username or 'Not set'}. Login at: {login_url}"
        )

        # Log the result
        if success:
            self.logger.info("Username recovery email sent successfully", extra={
                'email_type': 'username_recovery',
                'recipient': user_email  # Will be redacted
            })

            log_audit_event(
                action="send_username_recovery",
                resource="user_account",
                result="success",
                recipient_email=user_email  # Will be redacted
            )
        else:
            self.logger.error("Username recovery email send failed", extra={
                'email_type': 'username_recovery',
                'recipient': user_email  # Will be redacted
            })

        return success

    async def send_password_changed_notification(self, user_email: str, user_name: str) -> bool:
        """Send password changed notification email with dynamic URLs"""

        self.logger.info("Sending password changed notification", extra={
            'email_type': 'password_changed',
            'recipient': user_email,  # Will be redacted
            'user_name': user_name
        })

        # Use dynamic frontend URL for login page
        login_url = f"{self.frontend_url}/frontend/pages/auth/login.html"

        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Password Changed</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; background-color: #f4f4f4; }
                .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
                .header { text-align: center; margin-bottom: 30px; }
                .header h1 { color: #333; margin-bottom: 10px; }
                .content { margin-bottom: 30px; }
                .success-box { background-color: #d4edda; border: 2px solid #28a745; padding: 20px; text-align: center; border-radius: 10px; margin: 20px 0; color: #155724; }
                .footer { text-align: center; color: #666; font-size: 14px; border-top: 1px solid #eee; padding-top: 20px; margin-top: 30px; }
                .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 15px; border-radius: 5px; margin: 20px 0; }
                .env-info { background-color: #e7f3ff; border: 1px solid #b8daff; color: #004085; padding: 10px; border-radius: 5px; margin: 15px 0; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>✅ Password Successfully Changed</h1>
                    <p>Your account password has been updated</p>
                </div>

                <div class="content">
                    <p>Hi {{ user_name }}!</p>

                    <div class="success-box">
                        <strong>✅ Password Changed Successfully</strong>
                        <p>Your account password was changed at {{ timestamp }}</p>
                    </div>

                    <p>Your account is now secured with your new password. You can continue using your account normally.</p>

                    <div class="warning">
                        <strong>⚠️ Didn't change your password?</strong>
                        <p>If you didn't change your password, someone may have gained access to your account. Please contact support immediately and consider:</p>
                        <ul>
                            <li>Changing your password again</li>
                            <li>Checking your account for any unauthorized activity</li>
                            <li>Enabling two-factor authentication if available</li>
                        </ul>
                    </div>

                    {% if environment == 'development' %}
                    <div class="env-info">
                        <strong>🔧 Development Mode:</strong> Environment: {{ environment }} | Frontend: {{ frontend_url }} | API: {{ api_url }}
                    </div>
                    {% endif %}
                </div>

                <div class="footer">
                    <p>This is an automated security notification.</p>
                    <p>This is an automated message, please do not reply.</p>
                </div>
            </div>
        </body>
        </html>
        """

        # Render template with dynamic values
        template = Template(html_template)
        html_content = template.render(
            user_name=user_name,
            timestamp=datetime.now().strftime("%B %d, %Y at %I:%M %p UTC"),
            environment=self.environment,
            frontend_url=self.frontend_url,
            api_url=self.api_url
        )

        # Send email
        success = self.send_email(
            to_email=user_email,
            subject="✅ Password Changed - User Management System",
            html_content=html_content,
            text_content=f"Your password was successfully changed on {datetime.now().strftime('%B %d, %Y at %I:%M %p UTC')}. Login at: {login_url}"
        )

        # Log the result with security context (password changes are security events)
        if success:
            self.logger.info("Password changed notification sent successfully", extra={
                'email_type': 'password_changed',
                'recipient': user_email  # Will be redacted
            })

            log_security_event(
                event_type="password_change",
                action="send_notification",
                result="success",
                recipient_email=user_email  # Will be redacted
            )
        else:
            self.logger.error("Password changed notification send failed", extra={
                'email_type': 'password_changed',
                'recipient': user_email  # Will be redacted
            })

            log_security_event(
                event_type="password_change",
                action="send_notification",
                result="failure",
                recipient_email=user_email  # Will be redacted
            )

        return success


# Create singleton instance
email_service = EmailService()


# Module-level function for easy importing
async def send_verification_email(user_email: str, user_name: str, verification_token: str) -> bool:
    """Send verification email - module level function"""
    return await email_service.send_verification_email(user_email, user_name, verification_token)


async def send_password_reset_email(user_email: str, user_name: str, reset_token: str) -> bool:
    """Send password reset email - module level function"""
    return await email_service.send_password_reset_email(user_email, user_name, reset_token)


async def send_username_recovery_email(user_email: str, user_name: str, username: str) -> bool:
    """Send username recovery email - module level function"""
    return await email_service.send_username_recovery_email(user_email, user_name, username)


async def send_password_changed_notification(user_email: str, user_name: str) -> bool:
    """Send password changed notification - module level function"""
    return await email_service.send_password_changed_notification(user_email, user_name)