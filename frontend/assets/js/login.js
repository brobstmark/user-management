// File: frontend/assets/js/login.js
// 🔒 Secure Login Page JavaScript - CSP Compliant

(function() {
    'use strict';

    // 🔒 Private scope to prevent global pollution
    let isSubmitting = false;
    let activeTimers = [];

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
                    page: 'login'
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
                            page: 'login'
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
                    page: 'login'
                });
            }

            // Auto-hide after 10 seconds
            setTimeout(() => {
                notice.style.display = 'none';
            }, 10000);
        }
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

        if (type === 'email' && value) {
            // 🔒 More strict email validation
            const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
            if (!emailRegex.test(value) || value.length > 254) {
                isValid = false;
                message = 'Please enter a valid email address';
            }
        }

        if (type === 'password' && value) {
            if (value.length < 8 || value.length > 128) {
                isValid = false;
                message = 'Password must be 8-128 characters long';
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
                        page: 'login'
                    });
                }
            } else {
                validationDiv.style.display = 'none';
            }
        }

        return isValid;
    }

    // 🔒 Prevent XSS in URL parameters
    function sanitizeUrlParams() {
        const urlParams = new URLSearchParams(window.location.search);
        const allowedParams = ['redirect', 'email'];

        let paramsCleaned = false;
        for (const [key, value] of urlParams.entries()) {
            if (!allowedParams.includes(key)) {
                urlParams.delete(key);
                paramsCleaned = true;
            }
        }

        // 🔒 Log parameter sanitization
        if (paramsCleaned && window.logSecurityEvent) {
            window.logSecurityEvent('url_parameters_sanitized', {
                action: 'remove_disallowed_params',
                page: 'login'
            });
        }

        // Pre-fill email if provided and valid
        const email = urlParams.get('email');
        if (email) {
            // 🔒 Strict validation before prefilling
            const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
            if (emailRegex.test(email) && email.length <= 254) {
                const emailInput = document.getElementById('email');
                if (emailInput) {
                    emailInput.value = email;

                    // 🔒 Log email prefill
                    if (window.logInfo) {
                        window.logInfo('Email prefilled from URL parameter', {
                            action: 'email_prefill',
                            page: 'login'
                        });
                    }
                }
            }
        }
    }

    // 🔒 Initialize event listeners
    function initializeEventListeners() {
        // Password visibility toggle
        const passwordToggle = document.getElementById('passwordToggle');
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
                        action: 'password_toggle',
                        visible: !isPassword,
                        page: 'login'
                    });
                }

                // Refocus password input
                passwordInput.focus();
            });
        }

        // Real-time validation listeners
        const emailInput = document.getElementById('email');
        const passwordInput = document.getElementById('password');

        if (emailInput) {
            emailInput.addEventListener('blur', function() {
                validateInput(this);
            });
        }

        if (passwordInput) {
            passwordInput.addEventListener('blur', function() {
                validateInput(this);
            });
        }

        // 🔒 Form submission with race condition protection
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', function(e) {
                e.preventDefault();

                // 🔒 Prevent double submission
                if (isSubmitting) {
                    if (window.logWarn) {
                        window.logWarn('Blocked duplicate form submission', {
                            page: 'login'
                        });
                    }
                    return;
                }

                // 🔒 Log login attempt
                if (window.logAuthEvent) {
                    window.logAuthEvent('login_form_submission', {
                        action: 'form_submit',
                        page: 'login',
                        user_agent: navigator.userAgent.substring(0, 100)
                    });
                }

                // Validate all inputs before submission
                const emailValid = validateInput(emailInput);
                const passwordValid = validateInput(passwordInput);

                if (!emailValid || !passwordValid) {
                    displayMessage('Please fix the validation errors before submitting.', 'error');

                    // 🔒 Log validation failure
                    if (window.logSecurityEvent) {
                        window.logSecurityEvent('login_validation_failure', {
                            email_valid: emailValid,
                            password_valid: passwordValid,
                            page: 'login'
                        });
                    }

                    return;
                }

                // Set submitting state
                isSubmitting = true;
                const submitButton = document.getElementById('loginBtn');
                const spinner = document.getElementById('loadingSpinner');
                const buttonText = document.getElementById('buttonText');

                if (submitButton) submitButton.disabled = true;
                if (spinner) spinner.style.display = 'inline-block';
                if (buttonText) buttonText.textContent = 'Signing In...';

                // Continue with auth.js login logic
                if (window.handleLogin) {
                    window.handleLogin(e).finally(() => {
                        // Reset submission state
                        isSubmitting = false;
                        if (submitButton) submitButton.disabled = false;
                        if (spinner) spinner.style.display = 'none';
                        if (buttonText) buttonText.textContent = 'Sign In';
                    });
                } else {
                    // Reset if no handler
                    isSubmitting = false;
                    if (submitButton) submitButton.disabled = false;
                    if (spinner) spinner.style.display = 'none';
                    if (buttonText) buttonText.textContent = 'Sign In';
                }
            });
        }
    }

    // 🔒 Secure global function exposure with read-only protection
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
            // Fallback to regular assignment if defineProperty fails
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
            // Log to console for development
            console.error('JavaScript Error:', e.message);

            // 🔒 Log to backend security system
            if (window.logError) {
                window.logError('JavaScript Error on Login Page', {
                    message: e.message,
                    filename: e.filename,
                    lineno: e.lineno,
                    page: 'login',
                    error_type: 'javascript_error'
                });
            }

            // Don't expose error details to users
            displayMessage('An unexpected error occurred. Please try again.', 'error');
        });
    }

    // 🔒 Initialize everything when DOM is ready
    document.addEventListener('DOMContentLoaded', function() {
        sanitizeUrlParams();
        initializeEventListeners();
        exposeSecureFunctions();
        setupCleanup();
        setupSecurityMonitoring();

        // 🔒 Log page initialization
        if (window.logInfo) {
            window.logInfo('Login page initialized', {
                page: 'login',
                url: window.location.href,
                referrer: document.referrer || 'direct'
            });
        }
    });

})();