/**
 * Clean Login Page Controller
 * Responsibilities: Form validation, UI state management, user interaction
 * Does NOT handle: API calls, authentication logic, session management
 */

(function() {
    'use strict';

    // Private scope variables
    let isSubmitting = false;
    let activeTimers = [];

    // Secure timer management
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

    // XSS-Safe Message Display
    function displayMessage(message, type = 'info') {
        const container = document.getElementById('messageContainer');
        if (!container) return;

        container.innerHTML = '';
        if (!message) return;

        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${type}`;
        messageDiv.textContent = String(message).substring(0, 500);
        container.appendChild(messageDiv);

        if (type === 'success') {
            setTimeout(() => {
                if (messageDiv.parentNode) {
                    messageDiv.parentNode.removeChild(messageDiv);
                }
            }, 5000);
        }
    }

    // Rate Limiting Display
    function showRateLimitWarning(seconds) {
        const warning = document.getElementById('rateLimitWarning');
        const countdown = document.getElementById('rateLimitCountdown');

        if (warning && countdown) {
            countdown.textContent = seconds;
            warning.style.display = 'block';

            const timerId = createSecureTimer(() => {
                seconds--;
                countdown.textContent = seconds;

                if (seconds <= 0) {
                    clearSecureTimer(timerId);
                    warning.style.display = 'none';
                }
            }, 1000);
        }
    }

    // Security Notice Display
    function showSecurityNotice(message) {
        const notice = document.getElementById('securityNotice');
        const messageSpan = document.getElementById('securityMessage');

        if (notice && messageSpan && message) {
            messageSpan.textContent = String(message).substring(0, 200);
            notice.style.display = 'block';

            setTimeout(() => {
                notice.style.display = 'none';
            }, 10000);
        }
    }

    // Input Validation
    function validateInput(input) {
        const value = input.value;
        const type = input.dataset.validate;
        const validationDiv = document.getElementById(input.id + 'Validation');

        let isValid = true;
        let message = '';

        input.classList.remove('input-validation-error');

        if (type === 'email' && value) {
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
            } else {
                validationDiv.style.display = 'none';
            }
        }

        return isValid;
    }

    // URL Parameter Sanitization
    function sanitizeUrlParams() {
        const urlParams = new URLSearchParams(window.location.search);
        const allowedParams = ['redirect', 'email', 'return_url'];

        let paramsCleaned = false;
        for (const [key, value] of urlParams.entries()) {
            if (!allowedParams.includes(key)) {
                urlParams.delete(key);
                paramsCleaned = true;
            }
        }

        // Pre-fill email if provided and valid
        const email = urlParams.get('email');
        if (email) {
            const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
            if (emailRegex.test(email) && email.length <= 254) {
                const emailInput = document.getElementById('email');
                if (emailInput) {
                    emailInput.value = email;
                }
            }
        }
    }

    // Button Loading State Management
    function setButtonLoadingState(button, loadingText, isLoading = true) {
        if (!button) return;

        if (isLoading) {
            button.disabled = true;
            const spinner = button.querySelector('#loadingSpinner');
            const buttonText = button.querySelector('#buttonText');

            if (spinner) spinner.style.display = 'inline-block';
            if (buttonText) buttonText.textContent = loadingText;
        } else {
            button.disabled = false;
            const spinner = button.querySelector('#loadingSpinner');
            const buttonText = button.querySelector('#buttonText');

            if (spinner) spinner.style.display = 'none';
            if (buttonText) buttonText.textContent = loadingText;
        }
    }

    // Main Login Form Handler
    async function handleLoginFormSubmission(e) {
        e.preventDefault();

        // Prevent double submission
        if (isSubmitting) {
            console.warn('Duplicate form submission blocked');
            return;
        }

        const emailInput = document.getElementById('email');
        const passwordInput = document.getElementById('password');
        const loginBtn = document.getElementById('loginBtn');

        if (!emailInput || !passwordInput) {
            displayMessage('Form elements not found', 'error');
            return;
        }

        // Validate inputs
        const emailValid = validateInput(emailInput);
        const passwordValid = validateInput(passwordInput);

        if (!emailValid || !passwordValid) {
            displayMessage('Please fix the validation errors before submitting.', 'error');
            return;
        }

        const email = emailInput.value.trim();
        const password = passwordInput.value;

        if (!email || !password) {
            displayMessage('Please enter both email and password.', 'error');
            return;
        }

        // Set loading state
        isSubmitting = true;
        setButtonLoadingState(loginBtn, 'Signing In...', true);
        displayMessage(''); // Clear messages

        try {
            // Call auth API (auth.js responsibility)
            if (!window.Auth || typeof window.Auth.login !== 'function') {
                throw new Error('Authentication system not available');
            }

            const result = await window.Auth.login(email, password);
            console.log('LOGIN RESPONSE:', result);
            if (result.success) {
                displayMessage('Login successful! Redirecting...', 'success');
                // Auth.js handles the redirect
            } else {
                displayMessage(result.error || 'Login failed', 'error');
            }

        } catch (error) {
            console.error('Login error:', error);
            displayMessage('Connection error. Please try again.', 'error');
        } finally {
            // Reset form state
            isSubmitting = false;
            setButtonLoadingState(loginBtn, 'Sign In', false);
        }
    }

    // Initialize Event Listeners
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

        // Form submission handler
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            // Remove any existing listeners
            loginForm.removeEventListener('submit', handleLoginFormSubmission);
            // Add our clean handler
            loginForm.addEventListener('submit', handleLoginFormSubmission);
        }
    }

    // Expose necessary functions globally for backward compatibility
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
            // Fallback if defineProperty fails
            window.displayMessage = displayMessage;
            window.showRateLimitWarning = showRateLimitWarning;
            window.showSecurityNotice = showSecurityNotice;
        }
    }

    // Cleanup on page unload
    function setupCleanup() {
        window.addEventListener('beforeunload', function() {
            clearAllTimers();
        });

        window.addEventListener('pagehide', function() {
            clearAllTimers();
        });
    }

    // Security Monitoring
    function setupSecurityMonitoring() {
        window.addEventListener('error', function(e) {
            console.error('JavaScript Error:', e.message);
            displayMessage('An unexpected error occurred. Please try again.', 'error');
        });
    }

    // Initialize everything when DOM is ready
    document.addEventListener('DOMContentLoaded', function() {
        sanitizeUrlParams();
        initializeEventListeners();
        exposeSecureFunctions();
        setupCleanup();
        setupSecurityMonitoring();

        console.log('Login page controller initialized');
    });

})();