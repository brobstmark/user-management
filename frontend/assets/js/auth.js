/**
 * Secure Authentication JavaScript - Cookie-Based with CSRF Protection
 * Updated to use httpOnly cookies and CSRF tokens
 */

// 🔒 Secure Auth utility object
const Auth = {

    // Current CSRF token
    csrfToken: null,

    // Initialize authentication functionality
    async init() {
        this.setupFormHandlers();
        await this.initCSRF();
        await this.checkAuthStatus();
        this.setupSecurityMonitoring();

        // 🔒 Log initialization
        if (window.logInfo) {
            window.logInfo('Authentication module initialized', {
                module: 'auth',
                csrf_enabled: !!this.csrfToken
            });
        }
    },

    // Initialize CSRF protection
    async initCSRF() {
        try {
            const response = await window.AppConfig.apiRequest('/auth/csrf-token', {
                method: 'GET',
                credentials: 'same-origin'  // Include cookies
            });

            if (response.ok) {
                const data = await response.json();
                this.csrfToken = data.csrf_token;

                if (window.logInfo) {
                    window.logInfo('CSRF token initialized', {
                        action: 'csrf_init'
                    });
                }
            }
        } catch (error) {
            if (window.logError) {
                window.logError('Failed to initialize CSRF token', {
                    error_type: error.name,
                    action: 'csrf_init'
                });
            }
        }
    },

    // Set up form event handlers
    setupFormHandlers() {
        // Login form
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', this.handleLogin.bind(this));
        }

        // Register form
        const registerForm = document.getElementById('registerForm');
        if (registerForm) {
            registerForm.addEventListener('submit', this.handleRegister.bind(this));
        }

        // Forgot password form
        const forgotPasswordForm = document.getElementById('forgotPasswordForm');
        if (forgotPasswordForm) {
            forgotPasswordForm.addEventListener('submit', this.handleForgotPassword.bind(this));
        }

        // Forgot username form
        const forgotUsernameForm = document.getElementById('forgotUsernameForm');
        if (forgotUsernameForm) {
            forgotUsernameForm.addEventListener('submit', this.handleForgotUsername.bind(this));
        }

        // Add real-time validation
        this.setupValidation();
    },

    // 🔒 Check authentication status using backend endpoint
    async checkAuthStatus() {
        const currentPage = window.location.pathname;

        try {
            const response = await window.AppConfig.apiRequest('/auth/auth-status', {
                method: 'GET',
                credentials: 'same-origin'  // Include httpOnly cookies
            });

            const isAuthenticated = response.ok;

            // 🔒 Log authentication check
            if (window.logInfo) {
                window.logInfo('Authentication status checked', {
                    authenticated: isAuthenticated,
                    page: currentPage.split('/').pop()
                });
            }

            // If on login/register page and already authenticated, redirect to dashboard
            if (isAuthenticated && (currentPage.includes('login.html') || currentPage.includes('register.html'))) {
                this.secureRedirect('../user/dashboard.html');
            }

            // If on protected page and not authenticated, redirect to login
            if (!isAuthenticated && currentPage.includes('dashboard.html')) {
                this.secureRedirect('../auth/login.html');
            }

            return isAuthenticated;

        } catch (error) {
            // Not authenticated or connection error
            if (window.logInfo) {
                window.logInfo('Authentication check failed', {
                    error_type: error.name,
                    page: currentPage.split('/').pop()
                });
            }

            // If on protected page, redirect to login
            if (currentPage.includes('dashboard.html')) {
                this.secureRedirect('../auth/login.html');
            }

            return false;
        }
    },

    // 🔒 Create authenticated request with CSRF token
    async authenticatedRequest(endpoint, options = {}) {
        const requestOptions = {
            ...options,
            credentials: 'same-origin',  // Include httpOnly cookies
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        };

        // Add CSRF token for state-changing requests
        if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(options.method?.toUpperCase())) {
            if (this.csrfToken) {
                requestOptions.headers['X-CSRF-Token'] = this.csrfToken;
            } else {
                // Try to get CSRF token if we don't have one
                await this.initCSRF();
                if (this.csrfToken) {
                    requestOptions.headers['X-CSRF-Token'] = this.csrfToken;
                }
            }
        }

        return window.AppConfig?.apiRequest(endpoint, requestOptions) ||
               Promise.reject(new Error('AppConfig not available'));
    },

    // 🔒 Secure redirect function to prevent open redirects
    secureRedirect(path) {
        // Validate that path is relative and doesn't contain dangerous patterns
        if (typeof path !== 'string' ||
            path.startsWith('http://') ||
            path.startsWith('https://') ||
            path.startsWith('//') ||
            path.includes('javascript:') ||
            path.includes('data:')) {

            if (window.logSecurityEvent) {
                window.logSecurityEvent('blocked_dangerous_redirect', {
                    attempted_path: path,
                    reason: 'potential_open_redirect'
                });
            }
            return;
        }

        // 🔒 Log secure redirect
        if (window.logInfo) {
            window.logInfo('Performing secure redirect', {
                destination: path
            });
        }

        window.location.href = path;
    },

    // Handle login form submission
    async handleLogin(e) {
        e.preventDefault();

        const email = document.getElementById('email')?.value?.trim();
        const password = document.getElementById('password')?.value;
        const loginBtn = document.getElementById('loginBtn');

        // 🔒 Input validation
        if (!email || !password) {
            this.showMessage('error', '⚠️ Missing Information', 'Please enter both email and password.');
            return;
        }

        // 🔒 Log login attempt (email will be redacted)
        if (window.logAuthEvent) {
            window.logAuthEvent('login_attempt', {
                action: 'login_form_submit',
                email: email // Will be redacted by logger
            });
        }

        // Clear previous messages
        this.clearMessages();

        // Disable button and show loading
        this.setButtonLoading(loginBtn, 'Signing In...');

        try {
            const response = await this.authenticatedRequest('/auth/login', {
                method: 'POST',
                body: JSON.stringify({
                    email: email,
                    password: password
                })
            });

            const data = await response.json();

            if (response.ok) {
                // 🔒 Log successful login
                if (window.logAuthEvent) {
                    window.logAuthEvent('login_success', {
                        action: 'login_successful',
                        email: email // Will be redacted
                    });
                }

                this.showMessage('success', '✅ Welcome back!', 'Redirecting to your dashboard...');

                setTimeout(() => {
                    this.secureRedirect('../user/dashboard.html');
                }, 1500);

            } else {
                // 🔒 Secure error handling - don't expose server details
                let errorMessage = 'Login failed';

                if (response.status === 401) {
                    errorMessage = 'Invalid email or password';
                } else if (response.status === 422) {
                    errorMessage = 'Please check your email and password format';
                } else if (response.status === 429) {
                    errorMessage = 'Too many login attempts. Please try again later.';
                } else if (response.status >= 500) {
                    errorMessage = 'Server temporarily unavailable. Please try again later.';
                }

                // 🔒 Log failed login attempt
                if (window.logSecurityEvent) {
                    window.logSecurityEvent('login_failure', {
                        action: 'login_failed',
                        status_code: response.status,
                        email: email // Will be redacted
                    });
                }

                this.showMessage('error', `❌ ${errorMessage}`, 'Please try again or reset your password if needed.');
            }
        } catch (error) {
            // 🔒 Log connection error
            if (window.logError) {
                window.logError('Login connection error', {
                    error_type: error.name,
                    action: 'login_request'
                });
            }

            this.showMessage('error', '❌ Connection Error', 'Unable to connect to the server. Please check your internet connection and try again.');
        } finally {
            this.setButtonLoading(loginBtn, 'Sign In', false);
        }
    },

    // Handle registration form submission
    async handleRegister(e) {
        e.preventDefault();

        const formData = new FormData(e.target);
        const data = Object.fromEntries(formData);
        const registerBtn = document.getElementById('registerBtn');

        // 🔒 Input sanitization and validation
        const email = data.email?.trim();
        const password = data.password;
        const confirmPassword = data.confirmPassword;
        const firstName = data.firstName?.trim();
        const lastName = data.lastName?.trim();

        // Validate required fields
        if (!email || !password) {
            this.showMessage('error', '❌ Missing Information', 'Email and password are required.');
            return;
        }

        // Validate passwords match
        if (password !== confirmPassword) {
            this.showMessage('error', '❌ Passwords Don\'t Match', 'Please make sure both password fields are identical.');
            return;
        }

        // Validate password strength
        if (!this.validatePasswordStrength(password)) {
            this.showMessage('error', '❌ Password Too Weak', 'Please ensure your password meets all the requirements.');
            return;
        }

        // 🔒 Log registration attempt
        if (window.logAuthEvent) {
            window.logAuthEvent('registration_attempt', {
                action: 'register_form_submit',
                email: email // Will be redacted
            });
        }

        this.clearMessages();
        this.setButtonLoading(registerBtn, 'Creating Account...');

        try {
            // Note: Registration doesn't need authentication, so we use regular apiRequest
            const response = await window.AppConfig.apiRequest('/auth/register', {
                method: 'POST',
                body: JSON.stringify({
                    email: email,
                    password: password,
                    first_name: firstName || null,
                    last_name: lastName || null
                })
            });

            const result = await response.json();

            if (response.ok) {
                // 🔒 Log successful registration
                if (window.logAuthEvent) {
                    window.logAuthEvent('registration_success', {
                        action: 'registration_successful',
                        email: email // Will be redacted
                    });
                }

                this.showMessage('success', '✅ Account Created Successfully!',
                    'Please check your email for a verification link before logging in.');

                // Clear form
                e.target.reset();

                // Redirect to login after delay
                setTimeout(() => {
                    this.secureRedirect('login.html');
                }, 3000);

            } else {
                // 🔒 Secure error handling
                let errorMessage = 'Registration failed';

                if (response.status === 422) {
                    errorMessage = 'Please check your input and try again';
                } else if (response.status === 409) {
                    errorMessage = 'An account with this email already exists';
                } else if (response.status === 429) {
                    errorMessage = 'Too many registration attempts. Please try again later.';
                }

                // 🔒 Log failed registration
                if (window.logSecurityEvent) {
                    window.logSecurityEvent('registration_failure', {
                        action: 'registration_failed',
                        status_code: response.status,
                        email: email // Will be redacted
                    });
                }

                this.showMessage('error', '❌ Registration Failed', errorMessage);
            }
        } catch (error) {
            // 🔒 Log connection error
            if (window.logError) {
                window.logError('Registration connection error', {
                    error_type: error.name,
                    action: 'registration_request'
                });
            }

            this.showMessage('error', '❌ Connection Error', 'Unable to connect to the server. Please try again.');
        } finally {
            this.setButtonLoading(registerBtn, 'Create Account', false);
        }
    },

    // Handle forgot password form submission
    async handleForgotPassword(e) {
        e.preventDefault();

        const email = document.getElementById('email')?.value?.trim();
        const forgotBtn = document.getElementById('forgotBtn');

        if (!email) {
            this.showMessage('error', '❌ Email Required', 'Please enter your email address.');
            return;
        }

        // 🔒 Log forgot password attempt
        if (window.logAuthEvent) {
            window.logAuthEvent('forgot_password_attempt', {
                action: 'forgot_password_submit',
                email: email // Will be redacted
            });
        }

        this.clearMessages();
        this.setButtonLoading(forgotBtn, 'Sending Email...');

        try {
            // Note: Forgot password doesn't need authentication
            const response = await window.AppConfig.apiRequest('/auth/forgot-password', {
                method: 'POST',
                body: JSON.stringify({ email })
            });

            // Always show success message for security (prevent email enumeration)
            this.showMessage('success', '✅ Reset Email Sent',
                'If an account with this email exists, you will receive a password reset link shortly.');

            // 🔒 Log forgot password request (always log as success to prevent enumeration)
            if (window.logAuthEvent) {
                window.logAuthEvent('forgot_password_requested', {
                    action: 'forgot_password_sent',
                    email: email // Will be redacted
                });
            }

        } catch (error) {
            // 🔒 Log connection error
            if (window.logError) {
                window.logError('Forgot password connection error', {
                    error_type: error.name,
                    action: 'forgot_password_request'
                });
            }

            this.showMessage('error', '❌ Connection Error', 'Unable to send email. Please try again.');
        } finally {
            this.setButtonLoading(forgotBtn, 'Send Reset Email', false);
        }
    },

    // Handle forgot username form submission
    async handleForgotUsername(e) {
        e.preventDefault();

        const email = document.getElementById('email')?.value?.trim();
        const forgotBtn = document.getElementById('forgotBtn');

        if (!email) {
            this.showMessage('error', '❌ Email Required', 'Please enter your email address.');
            return;
        }

        // 🔒 Log forgot username attempt
        if (window.logAuthEvent) {
            window.logAuthEvent('forgot_username_attempt', {
                action: 'forgot_username_submit',
                email: email // Will be redacted
            });
        }

        this.clearMessages();
        this.setButtonLoading(forgotBtn, 'Sending Email...');

        try {
            // Note: Forgot username doesn't need authentication
            const response = await window.AppConfig.apiRequest('/auth/forgot-username', {
                method: 'POST',
                body: JSON.stringify({ email })
            });

            // Always show success message for security
            this.showMessage('success', '✅ Username Reminder Sent',
                'If an account with this email exists, you will receive your username shortly.');

            // 🔒 Log forgot username request
            if (window.logAuthEvent) {
                window.logAuthEvent('forgot_username_requested', {
                    action: 'forgot_username_sent',
                    email: email // Will be redacted
                });
            }

        } catch (error) {
            // 🔒 Log connection error
            if (window.logError) {
                window.logError('Forgot username connection error', {
                    error_type: error.name,
                    action: 'forgot_username_request'
                });
            }

            this.showMessage('error', '❌ Connection Error', 'Unable to send email. Please try again.');
        } finally {
            this.setButtonLoading(forgotBtn, 'Send Username', false);
        }
    },

    // 🔒 Secure logout functionality
    async logout() {
        // 🔒 Log logout attempt
        if (window.logAuthEvent) {
            window.logAuthEvent('logout_attempt', {
                action: 'logout_initiated'
            });
        }

        try {
            await this.authenticatedRequest('/auth/logout', {
                method: 'POST'
            });
        } catch (error) {
            // Continue with logout even if request fails
            if (window.logError) {
                window.logError('Logout request failed', {
                    error_type: error.name,
                    action: 'logout_request'
                });
            }
        }

        this.secureRedirect('../auth/login.html');
    },

    // Check if user is authenticated
    async isAuthenticated() {
        try {
            const response = await window.AppConfig.apiRequest('/auth/auth-status', {
                method: 'GET',
                credentials: 'same-origin'
            });
            return response.ok;
        } catch (error) {
            return false;
        }
    },

    // Setup real-time validation (unchanged)
    setupValidation() {
        // Email validation
        const emailInputs = document.querySelectorAll('input[type="email"]');
        emailInputs.forEach(input => {
            input.addEventListener('blur', (e) => {
                this.validateEmail(e.target);
            });
        });

        // Password validation
        const passwordInputs = document.querySelectorAll('input[type="password"]');
        passwordInputs.forEach(input => {
            if (input.id === 'password') {
                input.addEventListener('input', (e) => {
                    this.updatePasswordRequirements(e.target.value);
                });
            }
        });

        // Confirm password validation
        const confirmPasswordInput = document.getElementById('confirmPassword');
        if (confirmPasswordInput) {
            confirmPasswordInput.addEventListener('input', (e) => {
                const password = document.getElementById('password')?.value || '';
                this.validatePasswordMatch(password, e.target.value, e.target);
            });
        }
    },

    // 🔒 Enhanced email validation (unchanged)
    validateEmail(input) {
        const email = input.value?.trim();
        // RFC 5322 compliant email regex (simplified but more secure)
        const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

        if (email && (!emailRegex.test(email) || email.length > 254)) {
            input.classList.add('error');
            this.showFieldError(input, 'Please enter a valid email address');
            return false;
        } else if (email) {
            input.classList.remove('error');
            input.classList.add('success');
            this.hideFieldError(input);
            return true;
        }
        return true;
    },

    // Validate password strength (unchanged)
    validatePasswordStrength(password) {
        if (!password) return false;

        const minLength = password.length >= 8 && password.length <= 128;
        const hasUpper = /[A-Z]/.test(password);
        const hasLower = /[a-z]/.test(password);
        const hasNumber = /\d/.test(password);
        const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\?]/.test(password);

        return minLength && hasUpper && hasLower && hasNumber && hasSpecial;
    },

    // Update password requirements display (unchanged)
    updatePasswordRequirements(password) {
        const requirements = document.querySelectorAll('.password-requirements li');
        if (requirements.length === 0) return;

        const checks = [
            password.length >= 8 && password.length <= 128,
            /[A-Z]/.test(password) && /[a-z]/.test(password),
            /\d/.test(password),
            /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\?]/.test(password)
        ];

        requirements.forEach((req, index) => {
            if (checks[index]) {
                req.classList.add('valid');
            } else {
                req.classList.remove('valid');
            }
        });
    },

    // Validate password match (unchanged)
    validatePasswordMatch(password, confirmPassword, input) {
        if (confirmPassword && password !== confirmPassword) {
            input.classList.add('error');
            this.showFieldError(input, 'Passwords do not match');
            return false;
        } else if (confirmPassword) {
            input.classList.remove('error');
            input.classList.add('success');
            this.hideFieldError(input);
            return true;
        }
        return true;
    },

    // Show field-specific error (unchanged)
    showFieldError(input, message) {
        this.hideFieldError(input);
        const error = document.createElement('span');
        error.className = 'field-error';
        error.textContent = message; // 🔒 Use textContent to prevent XSS
        input.parentNode.appendChild(error);
    },

    // Hide field-specific error (unchanged)
    hideFieldError(input) {
        const error = input.parentNode.querySelector('.field-error');
        if (error) {
            error.remove();
        }
    },

    // 🔒 XSS-safe message display (unchanged)
    showMessage(type, title, description = '') {
        const messageContainer = document.getElementById('message-container') ||
                                document.getElementById('messageContainer');
        if (!messageContainer) {
            // Use global message function if available
            if (window.displayMessage) {
                window.displayMessage(`${title}. ${description}`, type);
            }
            return;
        }

        // Clear previous messages
        messageContainer.innerHTML = '';

        // 🔒 Create elements safely to prevent XSS
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${type}`;

        const titleElement = document.createElement('strong');
        titleElement.textContent = String(title).substring(0, 100); // Limit length

        messageDiv.appendChild(titleElement);

        if (description) {
            messageDiv.appendChild(document.createElement('br'));
            const descElement = document.createElement('span');
            descElement.textContent = String(description).substring(0, 300); // Limit length
            messageDiv.appendChild(descElement);
        }

        messageContainer.appendChild(messageDiv);

        // Auto-remove success messages
        if (type === 'success') {
            setTimeout(() => {
                if (messageDiv.parentNode) {
                    messageDiv.parentNode.removeChild(messageDiv);
                }
            }, 5000);
        }
    },

    // Clear all messages (unchanged)
    clearMessages() {
        const messageContainer = document.getElementById('message-container') ||
                                document.getElementById('messageContainer');
        if (messageContainer) {
            messageContainer.innerHTML = '';
        }
    },

    // 🔒 Secure button loading state (unchanged)
    setButtonLoading(button, loadingText, loading = true) {
        if (!button) return;

        if (loading) {
            button.disabled = true;
            // 🔒 Create spinner safely
            const spinner = document.createElement('span');
            spinner.className = 'loading-spinner';

            const text = document.createElement('span');
            text.textContent = String(loadingText).substring(0, 50); // Limit length

            button.innerHTML = '';
            button.appendChild(spinner);
            button.appendChild(text);
        } else {
            button.disabled = false;
            button.textContent = String(loadingText).substring(0, 50);
        }
    },

    // 🔒 Setup security monitoring (unchanged)
    setupSecurityMonitoring() {
        // Monitor for suspicious activity
        let suspiciousAttempts = 0;
        const maxAttempts = 5;

        // Monitor rapid form submissions
        let lastSubmission = 0;
        document.addEventListener('submit', (e) => {
            const now = Date.now();
            if (now - lastSubmission < 1000) { // Less than 1 second
                suspiciousAttempts++;
                if (suspiciousAttempts > maxAttempts && window.logSecurityEvent) {
                    window.logSecurityEvent('rapid_form_submissions_detected', {
                        attempts: suspiciousAttempts,
                        time_window: '1_second'
                    });
                }
            }
            lastSubmission = now;
        });

        // Monitor for authentication state changes
        setInterval(async () => {
            try {
                const isAuth = await this.isAuthenticated();
                if (!isAuth && window.location.pathname.includes('dashboard.html')) {
                    if (window.logSecurityEvent) {
                        window.logSecurityEvent('session_expired', {
                            action: 'redirect_to_login'
                        });
                    }
                    this.secureRedirect('../auth/login.html');
                }
            } catch (error) {
                // Silently handle errors
            }
        }, 30000); // Check every 30 seconds
    }
};

// Initialize authentication when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    Auth.init();
});

// 🔒 Expose Auth globally with protection
try {
    Object.defineProperty(window, 'Auth', {
        value: Auth,
        writable: false,
        configurable: false
    });
} catch (e) {
    // Fallback if defineProperty fails
    window.Auth = Auth;
}

// 🔒 Global function for backward compatibility
window.handleLogin = Auth.handleLogin.bind(Auth);