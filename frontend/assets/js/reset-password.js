// File: frontend/assets/js/reset-password.js
// 🔒 Secure Reset Password Page JavaScript - CSP Compliant

(function() {
    'use strict';

    // 🔒 Private scope to prevent global pollution
    let isSubmitting = false;
    let activeTimers = [];
    let resetToken = null;

    // 🔒 Secure timer management
    function createSecureTimer(callback, interval) {
        const timerId = setInterval(callback, interval);
        activeTimers.push(timerId);
        return timerId;
    }

    function clearSecureTimer(timerId) {
        clearInterval(timerId);
        const index = activeTimers.indexOf(timerId);
        if (index > -1) {
            activeTimers.splice(index, 1);
        }
    }

    function clearAllTimers() {
        activeTimers.forEach(timerId => clearInterval(timerId));
        activeTimers = [];
    }

    // 🔒 XSS-Safe Message Display Function
    function displayMessage(message, type = 'info') {
        const container = document.getElementById('messageContainer');
        if (!container) return;

        // Clear previous messages
        container.innerHTML = '';
        if (!message) return;

        // 🛡️ XSS PROTECTION: Create element safely
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${type}`;

        // 🛡️ XSS PROTECTION: Use textContent instead of innerHTML
        messageDiv.textContent = String(message).substring(0, 500);
        container.appendChild(messageDiv);

        // Auto-remove success messages after 5 seconds
        if (type === 'success') {
            setTimeout(() => {
                if (messageDiv.parentNode) {
                    messageDiv.parentNode.removeChild(messageDiv);
                }
            }, 5000);
        }
    }

    // 🔒 Rate Limiting Display with secure timer
    function showRateLimitWarning(seconds) {
        const warning = document.getElementById('rateLimitWarning');
        const countdown = document.getElementById('rateLimitCountdown');

        if (warning && countdown) {
            countdown.textContent = seconds;
            warning.style.display = 'block';

            // 🔒 Log rate limiting event
            if (window.logSecurityEvent) {
                window.logSecurityEvent('rate_limit_warning_displayed', {
                    seconds_remaining: seconds,
                    page: 'reset-password'
                });
            }

            // 🔒 Secure countdown timer
            const timerId = createSecureTimer(() => {
                seconds--;
                countdown.textContent = seconds;

                if (seconds <= 0) {
                    clearSecureTimer(timerId);
                    warning.style.display = 'none';

                    // 🔒 Log rate limit expiry
                    if (window.logInfo) {
                        window.logInfo('Rate limit warning expired', {
                            page: 'reset-password'
                        });
                    }
                }
            }, 1000);
        }
    }

    // 🔒 Security Notice Display
    function showSecurityNotice(message) {
        const notice = document.getElementById('securityNotice');
        const messageSpan = document.getElementById('securityMessage');

        if (notice && messageSpan && message) {
            messageSpan.textContent = String(message).substring(0, 200);
            notice.style.display = 'block';

            // 🔒 Log security notice
            if (window.logSecurityEvent) {
                window.logSecurityEvent('security_notice_displayed', {
                    message: message,
                    page: 'reset-password'
                });
            }

            // Auto-hide after 10 seconds
            setTimeout(() => {
                notice.style.display = 'none';
            }, 10000);
        }
    }

    // 🔒 Extract and validate reset token from URL
    function extractResetToken() {
        const urlParams = new URLSearchParams(window.location.search);
        const token = urlParams.get('token');

        if (!token) {
            displayMessage('Invalid reset link. This reset link is invalid or malformed. Please request a new password reset.', 'error');
            document.getElementById('resetFormContainer').style.display = 'none';

            // 🔒 Log invalid token access
            if (window.logSecurityEvent) {
                window.logSecurityEvent('invalid_reset_token_access', {
                    page: 'reset-password',
                    has_token: false,
                    url: window.location.href
                });
            }
            return null;
        }

        // Basic token format validation
        if (token.length < 10 || !/^[a-zA-Z0-9\-_]+$/.test(token)) {
            displayMessage('Invalid reset token format. Please request a new password reset.', 'error');
            document.getElementById('resetFormContainer').style.display = 'none';

            // 🔒 Log malformed token
            if (window.logSecurityEvent) {
                window.logSecurityEvent('malformed_reset_token', {
                    page: 'reset-password',
                    token_length: token.length,
                    url: window.location.href
                });
            }
            return null;
        }

        // 🔒 Log successful token extraction
        if (window.logInfo) {
            window.logInfo('Reset token extracted and validated', {
                page: 'reset-password',
                token_length: token.length
            });
        }

        return token;
    }

    // 🔒 Real-time Input Validation
    function validateInput(input) {
        const value = input.value;
        const type = input.dataset.validate;
        const validationDiv = document.getElementById(input.id + 'Validation');

        let isValid = true;
        let message = '';

        // Remove previous validation styling
        input.classList.remove('input-validation-error');

        if (type === 'password' && value) {
            if (!_validatePasswordStrength(value)) {
                isValid = false;
                message = 'Password does not meet security requirements';
            }
        }

        if (type === 'confirmPassword' && value) {
            const password = document.getElementById('password')?.value || '';
            if (value && password !== value) {
                isValid = false;
                message = 'Passwords do not match';
            }
        }

        // Display validation message
        if (validationDiv) {
            if (!isValid && value) {
                input.classList.add('input-validation-error');
                validationDiv.textContent = message;
                validationDiv.style.display = 'block';

                // 🔒 Log validation error (rate limited)
                if (window.logWarn) {
                    window.logWarn('Input validation failed', {
                        field: input.id,
                        validation_type: type,
                        error: message,
                        page: 'reset-password'
                    });
                }
            } else {
                validationDiv.style.display = 'none';
            }
        }

        return isValid;
    }

    // 🔒 Validate password strength
    function _validatePasswordStrength(password) {
        if (!password) return false;

        const checks = [
            password.length >= 8 && password.length <= 128,
            /[A-Z]/.test(password),
            /[a-z]/.test(password),
            /\d/.test(password),
            /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\?]/.test(password)
        ];

        return checks.every(check => check);
    }

    // 🔒 Update password requirements display
    function updatePasswordRequirements(password) {
        const requirements = document.querySelectorAll('.password-requirements li');
        if (requirements.length === 0) return;

        const checks = [
            password.length >= 8 && password.length <= 128,
            /[A-Z]/.test(password) && /[a-z]/.test(password),
            /\d/.test(password),
            /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\?]/.test(password)
        ];

        requirements.forEach((req, index) => {
            req.classList.toggle('valid', checks[index]);
        });
    }

    // 🔒 Initialize button to correct state
    function initializeButtonState() {
        const submitButton = document.getElementById('resetBtn');
        const spinner = document.getElementById('loadingSpinner');
        const buttonText = document.getElementById('buttonText');

        // Ensure button is in normal state on load
        if (submitButton) {
            submitButton.disabled = false;
        }
        if (spinner) {
            spinner.style.display = 'none';
        }
        if (buttonText) {
            buttonText.textContent = 'Reset Password';
        }

        // Environment-aware logging
        if (window.AppConfig?.isDebug()) {
            console.log('Button state initialized', {
                disabled: submitButton?.disabled,
                spinnerVisible: spinner?.style.display,
                buttonText: buttonText?.textContent
            });
        }
    }

    // 🔒 Initialize event listeners
    function initializeEventListeners() {
        // Password visibility toggles
        const passwordToggle = document.getElementById('passwordToggle');
        const confirmPasswordToggle = document.getElementById('confirmPasswordToggle');

        if (passwordToggle) {
            passwordToggle.addEventListener('click', function() {
                const passwordInput = document.getElementById('password');
                if (!passwordInput) return;

                const isPassword = passwordInput.type === 'password';
                passwordInput.type = isPassword ? 'text' : 'password';
                this.textContent = isPassword ? '🙈' : '👁️';

                // 🔒 Log password visibility toggle
                if (window.logInfo) {
                    window.logInfo('Password visibility toggled', {
                        field: 'password',
                        visible: !isPassword,
                        page: 'reset-password'
                    });
                }
            });
        }

        if (confirmPasswordToggle) {
            confirmPasswordToggle.addEventListener('click', function() {
                const confirmPasswordInput = document.getElementById('confirmPassword');
                if (!confirmPasswordInput) return;

                const isPassword = confirmPasswordInput.type === 'password';
                confirmPasswordInput.type = isPassword ? 'text' : 'password';
                this.textContent = isPassword ? '🙈' : '👁️';
            });
        }

        // Real-time validation listeners
        const passwordInput = document.getElementById('password');
        const confirmPasswordInput = document.getElementById('confirmPassword');

        if (passwordInput) {
            passwordInput.addEventListener('input', function() {
                updatePasswordRequirements(this.value);
            });

            passwordInput.addEventListener('blur', function() {
                validateInput(this);
            });
        }

        if (confirmPasswordInput) {
            confirmPasswordInput.addEventListener('blur', function() {
                validateInput(this);
            });
        }

        // 🔒 Form submission with enhanced protection
        const resetForm = document.getElementById('resetPasswordForm');
        if (resetForm) {
            resetForm.addEventListener('submit', async function(e) {
                e.preventDefault();

                // 🔒 Enhanced double submission prevention
                if (isSubmitting) {
                    if (window.AppConfig?.isDebug()) {
                        console.warn('Blocked duplicate form submission - already submitting');
                    }
                    if (window.logWarn) {
                        window.logWarn('Blocked duplicate form submission', {
                            page: 'reset-password',
                            isSubmitting: isSubmitting
                        });
                    }
                    return false;
                }

                const password = passwordInput?.value;
                const confirmPassword = confirmPasswordInput?.value;

                if (!password || !confirmPassword) {
                    displayMessage('Please fill in all required fields.', 'error');
                    return false;
                }

                if (password !== confirmPassword) {
                    displayMessage('Passwords do not match. Please ensure both password fields are identical.', 'error');
                    return false;
                }

                if (!_validatePasswordStrength(password)) {
                    displayMessage('Password does not meet security requirements. Please ensure your password meets all the requirements listed.', 'error');
                    return false;
                }

                if (!resetToken) {
                    displayMessage('Invalid reset token. Please request a new password reset.', 'error');
                    return false;
                }

                // Environment-aware debug logging
                if (window.AppConfig?.isDebug()) {
                    console.log('Password reset form submission starting', {
                        hasToken: !!resetToken,
                        isSubmitting: isSubmitting
                    });
                }

                // 🔒 Log password reset attempt
                if (window.logAuthEvent) {
                    window.logAuthEvent('password_reset_form_submission', {
                        action: 'form_submit',
                        page: 'reset-password',
                        has_token: !!resetToken,
                        user_agent: navigator.userAgent.substring(0, 100)
                    });
                }

                // Set submitting state IMMEDIATELY
                isSubmitting = true;
                const submitButton = document.getElementById('resetBtn');
                const spinner = document.getElementById('loadingSpinner');
                const buttonText = document.getElementById('buttonText');

                if (submitButton) submitButton.disabled = true;
                if (spinner) spinner.style.display = 'inline-block';
                if (buttonText) buttonText.textContent = 'Resetting Password...';

                // Clear any previous messages
                displayMessage('');

                try {
                    // Use Auth class for consistency
                    if (window.Auth && window.Auth.resetPassword) {
                        const result = await window.Auth.resetPassword(resetToken, password);

                        if (window.AppConfig?.isDebug()) {
                            console.log('Auth.resetPassword completed', { success: result?.success });
                        }

                        if (result?.success) {
                            // Success - show success container and hide form
                            document.getElementById('resetFormContainer').style.display = 'none';
                            document.getElementById('successContainer').style.display = 'block';

                            // Update login link styling for success state
                            const loginLink = document.getElementById('loginLink');
                            if (loginLink) {
                                loginLink.textContent = '→ Go to Login';
                                loginLink.classList.add('success-link');
                            }
                        }
                    } else {
                        displayMessage('Authentication system not available. Please try again.', 'error');

                        if (window.logError) {
                            window.logError('Auth system not available on reset password page', {
                                page: 'reset-password'
                            });
                        }
                    }
                } catch (error) {
                    if (window.AppConfig?.isDebug()) {
                        console.error('Error in password reset submission:', error);
                    }

                    if (window.logError) {
                        window.logError('Error in password reset submission', {
                            error: error.message,
                            page: 'reset-password'
                        });
                    }

                    displayMessage('An error occurred while resetting your password. Please try again.', 'error');
                } finally {
                    // Reset submission state in finally block
                    isSubmitting = false;
                    if (submitButton) submitButton.disabled = false;
                    if (spinner) spinner.style.display = 'none';
                    if (buttonText) buttonText.textContent = 'Reset Password';

                    if (window.AppConfig?.isDebug()) {
                        console.log('Form submission state reset', { isSubmitting: isSubmitting });
                    }
                }

                return false;
            });
        }
    }

    // 🔒 Initialize configuration and environment indicator
    async function initializeConfiguration() {
        try {
            // Initialize configuration
            await window.AppConfig?.init();

            // Environment-aware logging
            if (window.AppConfig?.isDebug()) {
                console.log('Configuration loaded for reset password page');
            } else {
                if (window.logInfo) {
                    window.logInfo('Configuration loaded for reset password page', {
                        page: 'reset-password'
                    });
                }
            }

            // Show environment indicator if debug mode
            if (window.AppConfig?.isDebug()) {
                const environment = window.AppConfig.getEnvironment();

                // Only show console message in development
                if (environment === 'development') {
                    console.log('Development mode: Enhanced debugging enabled');
                }

                document.body.insertAdjacentHTML('afterbegin',
                    `<div style="background: #17a2b8; color: white; padding: 5px 10px; text-align: center; font-size: 12px;">
                        DEVELOPMENT MODE - ${environment.toUpperCase()}
                    </div>`
                );

                if (window.logInfo) {
                    window.logInfo('Development mode indicator displayed', {
                        environment: environment,
                        page: 'reset-password'
                    });
                }
            }

        } catch (error) {
            // Environment-aware error logging
            if (window.AppConfig?.isDebug()) {
                console.warn('Config initialization failed:', error);
            }

            if (window.logWarn) {
                window.logWarn('Configuration initialization failed', {
                    error: error.message,
                    page: 'reset-password'
                });
            }
        }
    }

    // 🔒 Secure global function exposure
    function exposeSecureFunctions() {
        try {
            Object.defineProperty(window, 'displayMessage', {
                value: displayMessage,
                writable: false,
                configurable: false
            });

            Object.defineProperty(window, 'showRateLimitWarning', {
                value: showRateLimitWarning,
                writable: false,
                configurable: false
            });

            Object.defineProperty(window, 'showSecurityNotice', {
                value: showSecurityNotice,
                writable: false,
                configurable: false
            });
        } catch (e) {
            // Fallback to regular assignment
            window.displayMessage = displayMessage;
            window.showRateLimitWarning = showRateLimitWarning;
            window.showSecurityNotice = showSecurityNotice;
        }
    }

    // 🔒 Cleanup on page unload
    function setupCleanup() {
        window.addEventListener('beforeunload', function() {
            clearAllTimers();
        });

        window.addEventListener('pagehide', function() {
            clearAllTimers();
        });
    }

    // 🔒 Security Monitoring
    function setupSecurityMonitoring() {
        window.addEventListener('error', function(e) {
            if (window.AppConfig?.isDebug()) {
                console.error('JavaScript Error:', e.message);
            }

            if (window.logError) {
                window.logError('JavaScript Error on Reset Password Page', {
                    message: e.message,
                    filename: e.filename,
                    lineno: e.lineno,
                    page: 'reset-password',
                    error_type: 'javascript_error'
                });
            }

            displayMessage('An unexpected error occurred. Please try again.', 'error');
        });

        window.addEventListener('unhandledrejection', function(e) {
            if (window.AppConfig?.isDebug()) {
                console.error('Unhandled Promise Rejection:', e.reason);
            }

            if (window.logError) {
                window.logError('Unhandled Promise Rejection on Reset Password Page', {
                    reason: e.reason?.toString()?.substring(0, 500),
                    page: 'reset-password',
                    error_type: 'promise_rejection'
                });
            }
        });
    }

    // 🔒 Initialize everything when DOM is ready
    document.addEventListener('DOMContentLoaded', async function() {
        // Initialize in the correct order
        await initializeConfiguration();

        // Extract and validate token
        resetToken = extractResetToken();
        if (!resetToken) return; // Exit if no valid token

        initializeButtonState();
        initializeEventListeners();
        exposeSecureFunctions();
        setupCleanup();
        setupSecurityMonitoring();

        // 🔒 Log page initialization
        if (window.logInfo) {
            window.logInfo('Reset Password page initialized', {
                page: 'reset-password',
                url: window.location.href,
                has_token: !!resetToken,
                referrer: document.referrer || 'direct'
            });
        }
    });

})();