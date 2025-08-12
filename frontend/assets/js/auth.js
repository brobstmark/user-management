/**
 * Authentication JavaScript for User Management System
 */

// API Configuration is now handled by AppConfig
// No more hardcoded URLs! 🎉

// Auth utility object
const Auth = {

    // Initialize authentication functionality
    init() {
        this.setupFormHandlers();
        this.checkAuthStatus();
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

    // Check if user is authenticated
    checkAuthStatus() {
        const token = localStorage.getItem('access_token');
        const currentPage = window.location.pathname;

        // If on login/register page and already authenticated, redirect to dashboard
        if (token && (currentPage.includes('login.html') || currentPage.includes('register.html'))) {
            window.location.href = '../user/dashboard.html';
        }

        // If on protected page and not authenticated, redirect to login
        if (!token && currentPage.includes('dashboard.html')) {
            window.location.href = '../auth/login.html';
        }
    },

    // Handle login form submission
    async handleLogin(e) {
        e.preventDefault();

        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        const loginBtn = document.getElementById('loginBtn');
        const messageContainer = document.getElementById('message-container');

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

            if (response.ok) {
                // Success - store token and redirect
                localStorage.setItem('access_token', data.access_token);
                localStorage.setItem('user_email', email);

                this.showMessage('success', '✅ Welcome back!', 'Redirecting to your dashboard...');

                setTimeout(() => {
                    window.location.href = '../user/dashboard.html';
                }, 1500);

            } else {
                // Error handling
                let errorMessage = 'Login failed';

                if (response.status === 401) {
                    errorMessage = 'Invalid email or password';
                } else if (response.status === 422) {
                    errorMessage = 'Please check your email and password format';
                } else if (data.detail) {
                    errorMessage = typeof data.detail === 'string' ? data.detail : 'Login failed';
                }

                this.showMessage('error', `❌ ${errorMessage}`, 'Please try again or reset your password if needed.');
            }
        } catch (error) {
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

        // Validate passwords match
        if (data.password !== data.confirmPassword) {
            this.showMessage('error', '❌ Passwords Don\'t Match', 'Please make sure both password fields are identical.');
            return;
        }

        // Validate password strength
        if (!this.validatePasswordStrength(data.password)) {
            this.showMessage('error', '❌ Password Too Weak', 'Please ensure your password meets all the requirements.');
            return;
        }

        this.clearMessages();
        this.setButtonLoading(registerBtn, 'Creating Account...');

        try {
            const response = await window.AppConfig.apiRequest('/auth/register', {
                method: 'POST',
                body: JSON.stringify({
                    email: data.email,
                    password: data.password,
                    full_name: data.fullName || null,
                    phone_number: data.phone || null
                })
            });

            const result = await response.json();

            if (response.ok) {
                this.showMessage('success', '✅ Account Created Successfully!',
                    'Please check your email for a verification link before logging in.');

                // Clear form
                e.target.reset();

                // Redirect to login after delay
                setTimeout(() => {
                    window.location.href = 'login.html';
                }, 3000);

            } else {
                let errorMessage = result.detail || 'Registration failed';
                if (response.status === 422 && result.detail && Array.isArray(result.detail)) {
                    errorMessage = result.detail.map(err => err.msg).join(', ');
                }
                this.showMessage('error', '❌ Registration Failed', errorMessage);
            }
        } catch (error) {
            this.showMessage('error', '❌ Connection Error', 'Unable to connect to the server. Please try again.');
        } finally {
            this.setButtonLoading(registerBtn, 'Create Account', false);
        }
    },

    // Handle forgot password form submission
    async handleForgotPassword(e) {
        e.preventDefault();

        const email = document.getElementById('email').value;
        const forgotBtn = document.getElementById('forgotBtn');

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

        } catch (error) {
            this.showMessage('error', '❌ Connection Error', 'Unable to send email. Please try again.');
        } finally {
            this.setButtonLoading(forgotBtn, 'Send Reset Email', false);
        }
    },

    // Handle forgot username form submission
    async handleForgotUsername(e) {
        e.preventDefault();

        const email = document.getElementById('email').value;
        const forgotBtn = document.getElementById('forgotBtn');

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

        } catch (error) {
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
                const password = document.getElementById('password').value;
                this.validatePasswordMatch(password, e.target.value, e.target);
            });
        }
    },

    // Validate email format
    validateEmail(input) {
        const email = input.value;
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        if (email && !emailRegex.test(email)) {
            input.classList.add('error');
            this.showFieldError(input, 'Please enter a valid email address');
        } else {
            input.classList.remove('error');
            input.classList.add('success');
            this.hideFieldError(input);
        }
    },

    // Validate password strength
    validatePasswordStrength(password) {
        const minLength = password.length >= 8;
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
            password.length >= 8,
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
        } else if (confirmPassword) {
            input.classList.remove('error');
            input.classList.add('success');
            this.hideFieldError(input);
        }
    },

    // Show field-specific error
    showFieldError(input, message) {
        this.hideFieldError(input);
        const error = document.createElement('span');
        error.className = 'field-error';
        error.textContent = message;
        input.parentNode.appendChild(error);
    },

    // Hide field-specific error
    hideFieldError(input) {
        const error = input.parentNode.querySelector('.field-error');
        if (error) {
            error.remove();
        }
    },

    // Show message in message container
    showMessage(type, title, description = '') {
        const messageContainer = document.getElementById('message-container');
        if (!messageContainer) return;

        messageContainer.innerHTML = `
            <div class="message ${type}">
                <strong>${title}</strong>
                ${description ? `<br>${description}` : ''}
            </div>
        `;
    },

    // Clear all messages
    clearMessages() {
        const messageContainer = document.getElementById('message-container');
        if (messageContainer) {
            messageContainer.innerHTML = '';
        }
    },

    // Set button loading state
    setButtonLoading(button, loadingText, loading = true) {
        if (!button) return;

        if (loading) {
            button.disabled = true;
            button.innerHTML = `<span class="loading-spinner"></span>${loadingText}`;
        } else {
            button.disabled = false;
            button.innerHTML = loadingText;
        }
    },

    // Logout functionality
    logout() {
        localStorage.removeItem('access_token');
        localStorage.removeItem('user_email');
        window.location.href = '../auth/login.html';
    },

    // Get current user token
    getToken() {
        return localStorage.getItem('access_token');
    },

    // Check if user is authenticated
    isAuthenticated() {
        return !!this.getToken();
    },

    // Make authenticated API request
    async authenticatedRequest(endpoint, options = {}) {
        return window.AppConfig.apiRequest(endpoint, options);
    }
};

// Initialize authentication when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    Auth.init();
});

// Expose Auth globally
window.Auth = Auth;