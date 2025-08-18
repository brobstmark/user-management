/**
 * Secure Authentication JavaScript for User Management System
 * Enhanced with security fixes and logging integration
 */

// 🔒 Secure Auth utility object
const Auth = {

    // Initialize authentication functionality
    init() {
        this.setupFormHandlers();
        this.checkAuthStatus();
        this.setupSecurityMonitoring();

        // 🔒 Log initialization
        if (window.logInfo) {
            window.logInfo('Authentication module initialized', {
                module: 'auth',
                has_token: this.isAuthenticated()
            });
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

    // 🔒 Secure token storage with sessionStorage (more secure than localStorage)
    setToken(token) {
        try {
            // Use sessionStorage instead of localStorage for better security
            sessionStorage.setItem('access_token', token);

            // 🔒 Log token storage (token will be redacted)
            if (window.logAuthEvent) {
                window.logAuthEvent('token_stored', {
                    action: 'store_token',
                    storage_type: 'sessionStorage'
                });
            }
        } catch (error) {
            // Handle storage quota exceeded
            if (window.logError) {
                window.logError('Failed to store authentication token', {
                    error_type: error.name,
                    storage_type: 'sessionStorage'
                });
            }
            throw new Error('Unable to store authentication token');
        }
    },

    // 🔒 Secure token retrieval
    getToken() {
        try {
            return sessionStorage.getItem('access_token');
        } catch (error) {
            if (window.logError) {
                window.logError('Failed to retrieve authentication token', {
                    error_type: error.name
                });
            }
            return null;
        }
    },

    // 🔒 Secure token removal
    removeToken() {
        try {
            sessionStorage.removeItem('access_token');
            sessionStorage.removeItem('user_email');

            // 🔒 Log token removal
            if (window.logAuthEvent) {
                window.logAuthEvent('token_removed', {
                    action: 'remove_token',
                    reason: 'logout'
                });
            }
        } catch (error) {
            if (window.logError) {
                window.logError('Failed to remove authentication token', {
                    error_type: error.name
                });
            }
        }
    },

    // Check if user is authenticated
    checkAuthStatus() {
        const token = this.getToken();
        const currentPage = window.location.pathname;

        // 🔒 Log authentication check
        if (window.logInfo) {
            window.logInfo('Authentication status checked', {
                has_token: !!token,
                page: currentPage.split('/').pop()
            });
        }

        // If on login/register page and already authenticated, redirect to dashboard
        if (token && (currentPage.includes('login.html') || currentPage.includes('register.html'))) {
            // 🔒 Prevent open redirects by using relative paths only
            this.secureRedirect('../user/dashboard.html');
        }

        // If on protected page and not authenticated, redirect to login
        if (!token && currentPage.includes('dashboard.html')) {
            this.secureRedirect('../auth/login.html');
        }
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
            const response = await window.AppConfig.apiRequest('/auth/login', {
                method: 'POST',
                body: JSON.stringify({
                    email: email,
                    password: password
                })
            });

            const data = await response.json();

            if (response.ok && data.access_token) {
                // 🔒 Secure token storage
                this.setToken(data.access_token);

                // Store email in sessionStorage (less sensitive than token)
                try {
                    sessionStorage.setItem('user_email', email);
                } catch (error) {
                    // Non-critical, continue anyway
                }

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

    // Setup real-time validation
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

    // 🔒 Enhanced email validation
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

    // Validate password strength
    validatePasswordStrength(password) {
        if (!password) return false;

        const minLength = password.length >= 8 && password.length <= 128;
        const hasUpper = /[A-Z]/.test(password);
        const hasLower = /[a-z]/.test(password);
        const hasNumber = /\d/.test(password);
        const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\?]/.test(password);

        return minLength && hasUpper && hasLower && hasNumber && hasSpecial;
    },

    // Update password requirements display
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

    // Validate password match
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

    // Show field-specific error
    showFieldError(input, message) {
        this.hideFieldError(input);
        const error = document.createElement('span');
        error.className = 'field-error';
        error.textContent = message; // 🔒 Use textContent to prevent XSS
        input.parentNode.appendChild(error);
    },

    // Hide field-specific error
    hideFieldError(input) {
        const error = input.parentNode.querySelector('.field-error');
        if (error) {
            error.remove();
        }
    },

    // 🔒 XSS-safe message display
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

    // Clear all messages
    clearMessages() {
        const messageContainer = document.getElementById('message-container') ||
                                document.getElementById('messageContainer');
        if (messageContainer) {
            messageContainer.innerHTML = '';
        }
    },

    // 🔒 Secure button loading state
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

    // 🔒 Secure logout functionality
    logout() {
        // 🔒 Log logout attempt
        if (window.logAuthEvent) {
            window.logAuthEvent('logout_attempt', {
                action: 'logout_initiated'
            });
        }

        this.removeToken();
        this.secureRedirect('../auth/login.html');
    },

    // Check if user is authenticated
    isAuthenticated() {
        const token = this.getToken();
        return !!token && token.length > 0;
    },

    // Make authenticated API request
    async authenticatedRequest(endpoint, options = {}) {
        return window.AppConfig?.apiRequest(endpoint, options) ||
               Promise.reject(new Error('AppConfig not available'));
    },

    // 🔒 Setup security monitoring
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

        // Monitor for token manipulation
        let lastTokenCheck = this.getToken();
        setInterval(() => {
            const currentToken = this.getToken();
            if (lastTokenCheck !== currentToken && window.logSecurityEvent) {
                window.logSecurityEvent('token_change_detected', {
                    action: 'token_modified_outside_app'
                });
            }
            lastTokenCheck = currentToken;
        }, 5000);
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