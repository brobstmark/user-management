// File: frontend/assets/js/forgot-username.js
// 🔒 Secure Forgot Username Page JavaScript - CSP Compliant

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

        // Auto-remove success messages after 7 seconds
        if (type === 'success') {
            setTimeout(() => {
                if (messageDiv.parentNode) {
                    messageDiv.parentNode.removeChild(messageDiv);
                }
            }, 7000);
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
                    page: 'forgot-username'
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
                            page: 'forgot-username'
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
                    page: 'forgot-username'
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
                        page: 'forgot-username'
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
        const allowedParams = ['email'];

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
                page: 'forgot-username'
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
                            page: 'forgot-username'
                        });
                    }
                }
            }
        }
    }

    // 🔒 Initialize button to correct state
    function initializeButtonState() {
        const submitButton = document.getElementById('forgotBtn');
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
            buttonText.textContent = 'Send Username';
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
        // Real-time validation listener
        const emailInput = document.getElementById('email');

        if (emailInput) {
            emailInput.addEventListener('blur', function() {
                validateInput(this);
            });

            // Clear validation on focus
            emailInput.addEventListener('focus', function() {
                this.classList.remove('input-validation-error');
                const validationDiv = document.getElementById('emailValidation');
                if (validationDiv) {
                    validationDiv.style.display = 'none';
                }
            });
        }

        // 🔒 Form submission with enhanced race condition protection
        const forgotForm = document.getElementById('forgotUsernameForm');
        if (forgotForm) {
            forgotForm.addEventListener('submit', async function(e) {
                e.preventDefault();

                // 🔒 Enhanced double submission prevention
                if (isSubmitting) {
                    if (window.AppConfig?.isDebug()) {
                        console.warn('Blocked duplicate form submission - already submitting');
                    }
                    if (window.logWarn) {
                        window.logWarn('Blocked duplicate form submission', {
                            page: 'forgot-username',
                            isSubmitting: isSubmitting
                        });
                    }
                    return false;
                }

                const email = emailInput?.value?.trim();

                if (!email) {
                    displayMessage('Please enter your email address.', 'error');
                    emailInput?.focus();
                    return false;
                }

                // Environment-aware debug logging
                if (window.AppConfig?.isDebug()) {
                    console.log('Form submission starting', {
                        email: email ? '[EMAIL_PROVIDED]' : '[NO_EMAIL]',
                        isSubmitting: isSubmitting
                    });
                }

                // 🔒 Log forgot username attempt
                if (window.logAuthEvent) {
                    window.logAuthEvent('forgot_username_form_submission', {
                        action: 'form_submit',
                        page: 'forgot-username',
                        user_agent: navigator.userAgent.substring(0, 100)
                    });
                }

                // Validate email before submission
                const emailValid = validateInput(emailInput);

                if (!emailValid) {
                    displayMessage('Please enter a valid email address.', 'error');

                    // 🔒 Log validation failure
                    if (window.logSecurityEvent) {
                        window.logSecurityEvent('forgot_username_validation_failure', {
                            email_valid: emailValid,
                            page: 'forgot-username'
                        });
                    }

                    emailInput?.focus();
                    return false;
                }

                // Set submitting state IMMEDIATELY
                isSubmitting = true;
                const submitButton = document.getElementById('forgotBtn');
                const spinner = document.getElementById('loadingSpinner');
                const buttonText = document.getElementById('buttonText');

                if (submitButton) submitButton.disabled = true;
                if (spinner) spinner.style.display = 'inline-block';
                if (buttonText) buttonText.textContent = 'Sending Email...';

                // Clear any previous messages
                displayMessage('');

                // Environment-aware debug logging
                if (window.AppConfig?.isDebug()) {
                    console.log('Calling Auth.requestUsernameRecovery', { email: '[EMAIL_REDACTED]' });
                }

                try {
                    // Use Auth class to handle the request
                    if (window.Auth && window.Auth.requestUsernameRecovery) {
                        const result = await window.Auth.requestUsernameRecovery(email);

                        // Environment-aware debug logging
                        if (window.AppConfig?.isDebug()) {
                            console.log('Auth.requestUsernameRecovery completed', { success: result?.success });
                        }
                    } else {
                        // Fallback error if Auth not available
                        displayMessage('Authentication system not available. Please try again.', 'error');

                        if (window.logError) {
                            window.logError('Auth system not available on forgot username page', {
                                page: 'forgot-username'
                            });
                        }
                    }
                } catch (error) {
                    // Environment-aware error logging
                    if (window.AppConfig?.isDebug()) {
                        console.error('Error in forgot username submission:', error);
                    }

                    if (window.logError) {
                        window.logError('Error in forgot username submission', {
                            error: error.message,
                            page: 'forgot-username'
                        });
                    }

                    displayMessage('An error occurred. Please try again.', 'error');
                } finally {
                    // Reset submission state in finally block to ensure it always happens
                    isSubmitting = false;
                    if (submitButton) submitButton.disabled = false;
                    if (spinner) spinner.style.display = 'none';
                    if (buttonText) buttonText.textContent = 'Send Username';

                    // Environment-aware debug logging
                    if (window.AppConfig?.isDebug()) {
                        console.log('Form submission state reset', { isSubmitting: isSubmitting });
                    }
                }

                return false; // Prevent any other form submission
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
                console.log('Configuration loaded for forgot username page');
            } else {
                if (window.logInfo) {
                    window.logInfo('Configuration loaded for forgot username page', {
                        page: 'forgot-username'
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
                        page: 'forgot-username'
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
                    page: 'forgot-username'
                });
            }
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
            // Environment-aware error logging
            if (window.AppConfig?.isDebug()) {
                console.error('JavaScript Error:', e.message);
            }

            // 🔒 Log to backend security system
            if (window.logError) {
                window.logError('JavaScript Error on Forgot Username Page', {
                    message: e.message,
                    filename: e.filename,
                    lineno: e.lineno,
                    page: 'forgot-username',
                    error_type: 'javascript_error'
                });
            }

            // Don't expose error details to users
            displayMessage('An unexpected error occurred. Please try again.', 'error');
        });

        // Monitor potential security issues
        window.addEventListener('unhandledrejection', function(e) {
            if (window.AppConfig?.isDebug()) {
                console.error('Unhandled Promise Rejection:', e.reason);
            }

            if (window.logError) {
                window.logError('Unhandled Promise Rejection on Forgot Username Page', {
                    reason: e.reason?.toString()?.substring(0, 500),
                    page: 'forgot-username',
                    error_type: 'promise_rejection'
                });
            }
        });
    }

    // 🔒 Initialize everything when DOM is ready
    document.addEventListener('DOMContentLoaded', async function() {
        // Initialize in the correct order
        await initializeConfiguration();
        initializeButtonState(); // ← NEW: Initialize button to correct state
        sanitizeUrlParams();
        initializeEventListeners();
        exposeSecureFunctions();
        setupCleanup();
        setupSecurityMonitoring();

        // 🔒 Log page initialization
        if (window.logInfo) {
            window.logInfo('Forgot Username page initialized', {
                page: 'forgot-username',
                url: window.location.href,
                referrer: document.referrer || 'direct'
            });
        }
    });

})();