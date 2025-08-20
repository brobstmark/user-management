/**
 * 🔒 Secure Authentication System
 * Works with your existing httpOnly cookie backend
 * NO sessionStorage - Maximum Security
 */

class Auth {
    constructor() {
        this.isAuthenticated = false;
        this.userInfo = null;
        this.authCheckInterval = null;
        this.authEventListeners = [];
        this.csrfToken = null;
    }

    /**
     * Initialize authentication system
     */
    async init() {
        // Ensure config is loaded first
        if (!window.AppConfig?.loaded) {
            await window.AppConfig?.init();
        }

        // Skip auth checks on public pages
        const currentPage = window.location.pathname;
        const isPublicPage = currentPage.includes('login.html') ||
                           currentPage.includes('register.html') ||
                           currentPage.includes('forgot-password.html') ||
                           currentPage.includes('forgot-username.html');

        await this.initCSRF();
        this.setupFormHandlers();

        // Only check auth status on protected pages
        if (!isPublicPage) {
            await this.checkAuthStatus();
            this.setupAuthMonitoring();
        } else {
            // On public pages, just check if already authenticated for smart redirects
            const isAuth = await this._quickAuthCheck();
            if (isAuth && (currentPage.includes('login.html') || currentPage.includes('register.html'))) {
                this._secureRedirect('../user/dashboard.html');
            }
        }

        this.setupValidation();

        console.log('✅ Secure Authentication initialized');
    }

    /**
     * 🔒 Initialize CSRF protection
     */
    async initCSRF() {
        try {
            const url = window.AppConfig?.getApiUrl('/auth/csrf-token') || '/api/v1/auth/csrf-token';
            const response = await fetch(url, {
                method: 'GET',
                credentials: 'include'  // 🔒 Include httpOnly cookies
            });

            if (response.ok) {
                const data = await response.json();
                this.csrfToken = data.csrf_token;
                console.log('✅ CSRF token initialized');
            }
        } catch (error) {
            console.warn('⚠️ Failed to initialize CSRF token:', error.name);
        }
    }

    /**
     * 🔒 Make API request with proper cookie handling
     */
    async _apiRequest(endpoint, options = {}) {
        const url = window.AppConfig?.getApiUrl(endpoint) || `/api/v1${endpoint}`;

        const config = {
            credentials: 'include',  // 🔒 CRITICAL: Include httpOnly cookies
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        };

        // Add CSRF token for state-changing requests
        const method = options.method?.toUpperCase();
        if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method) && this.csrfToken) {
            config.headers['X-CSRF-Token'] = this.csrfToken;
        }

        try {
            const response = await fetch(url, config);

            // Handle auth errors - FIXED: only redirect from protected pages
            if (response.status === 401) {
                this.isAuthenticated = false;
                this.userInfo = null;
                this._triggerAuthEvent(false);

                const currentPage = window.location.pathname;
                // Only redirect if on dashboard or other protected pages, NOT from register/login
                if (currentPage.includes('dashboard.html') && !currentPage.includes('login.html') && !currentPage.includes('register.html')) {
                    this._secureRedirect('../auth/login.html');
                }
                return null;
            }

            return response;
        } catch (error) {
            console.error('🚨 API request failed:', error.name);
            throw error;
        }
    }

    /**
     * 🔒 Quick auth check for public pages (no redirects)
     */
    async _quickAuthCheck() {
        try {
            const url = window.AppConfig?.getApiUrl('/auth/auth-status') || '/api/v1/auth/auth-status';
            const response = await fetch(url, {
                method: 'GET',
                credentials: 'include'
            });
            return response?.ok || false;
        } catch (error) {
            return false;
        }
    }

    /**
     * 🔒 Check authentication status (server-side verification)
     */
    async checkAuthStatus() {
        try {
            // ✅ CORRECT ENDPOINT: /auth/auth-status (router has /auth prefix)
            const response = await this._apiRequest('/auth/auth-status', {
                method: 'GET'
            });

            if (response?.ok) {
                const data = await response.json();
                this.isAuthenticated = true;
                this.userInfo = data.user || null;
                this._triggerAuthEvent(true);
                this._handlePageAccess();
                return true;
            } else {
                this.isAuthenticated = false;
                this.userInfo = null;
                this._triggerAuthEvent(false);
                this._handlePageAccess();
                return false;
            }
        } catch (error) {
            console.warn('⚠️ Auth status check failed:', error.name);
            this.isAuthenticated = false;
            this.userInfo = null;
            this._triggerAuthEvent(false);
            this._handlePageAccess();
            return false;
        }
    }

    /**
     * 🔒 Handle login (httpOnly cookies only)
     */
    async login(email, password) {
        try {
            const response = await this._apiRequest('/auth/login', {
                method: 'POST',
                body: JSON.stringify({
                    email: email.trim(),
                    password: password
                })
            });

            if (response?.ok) {
                // Server sets httpOnly cookies automatically
                await this.checkAuthStatus(); // Refresh auth state

                console.log('✅ Login successful');
                this._showMessage('success', '✅ Welcome back!', 'Redirecting to dashboard...');

                setTimeout(() => {
                    this._secureRedirect('../user/dashboard.html');
                }, 1500);

                return { success: true };
            } else {
                let errorMessage = 'Login failed';

                switch (response?.status) {
                    case 401:
                        errorMessage = 'Invalid email or password';
                        break;
                    case 422:
                        errorMessage = 'Please check your email and password format';
                        break;
                    case 429:
                        errorMessage = 'Too many login attempts. Please try again later.';
                        break;
                    case 500:
                        errorMessage = 'Server temporarily unavailable. Please try again later.';
                        break;
                }

                this._showMessage('error', '❌ ' + errorMessage, 'Please try again or reset your password.');
                return { success: false, error: errorMessage };
            }
        } catch (error) {
            console.error('🚨 Login request failed:', error.name);
            this._showMessage('error', '❌ Connection Error', 'Unable to connect. Please try again.');
            return { success: false, error: 'Connection failed' };
        }
    }

    /**
     * 🔒 Handle registration
     */
    async register(userData) {
        try {
            const response = await this._apiRequest('/auth/register', {
                method: 'POST',
                body: JSON.stringify(userData)
            });

            if (response?.ok) {
                console.log('✅ Registration successful');
                this._showMessage('success', '✅ Account Created!',
                    'Please check your email for verification link.');

                setTimeout(() => {
                    this._secureRedirect('login.html');
                }, 3000);

                return { success: true };
            } else {
                let errorMessage = 'Registration failed';

                switch (response?.status) {
                    case 409:
                        errorMessage = 'An account with this email already exists';
                        break;
                    case 422:
                        errorMessage = 'Please check your input and try again';
                        break;
                    case 429:
                        errorMessage = 'Too many registration attempts. Please try again later.';
                        break;
                }

                this._showMessage('error', '❌ Registration Failed', errorMessage);
                return { success: false, error: errorMessage };
            }
        } catch (error) {
            console.error('🚨 Registration failed:', error.name);
            this._showMessage('error', '❌ Connection Error', 'Unable to connect. Please try again.');
            return { success: false, error: 'Connection failed' };
        }
    }

    /**
     * 🔒 Handle logout (clears httpOnly cookies)
     */
    async logout() {
        try {
            await this._apiRequest('/auth/logout', {
                method: 'POST'
            });
        } catch (error) {
            console.warn('⚠️ Logout request failed:', error.name);
        } finally {
            // Clear local state regardless of server response
            this.isAuthenticated = false;
            this.userInfo = null;
            this._triggerAuthEvent(false);

            console.log('✅ Logged out');
            this._secureRedirect('../auth/login.html');
        }
    }

    /**
     * 🔒 Request password reset
     */
    async requestPasswordReset(email) {
        try {
            await this._apiRequest('/auth/forgot-password', {
                method: 'POST',
                body: JSON.stringify({ email: email.trim() })
            });

            this._showMessage('success', '✅ Reset Email Sent',
                'If an account exists, you will receive a password reset link.');

            return { success: true };
        } catch (error) {
            console.error('🚨 Password reset request failed:', error.name);
            this._showMessage('error', '❌ Connection Error', 'Unable to send email. Please try again.');
            return { success: false, error: 'Connection failed' };
        }
    }

    /**
     * 🔒 Request username recovery
     */
    async requestUsernameRecovery(email) {
        try {
            await this._apiRequest('/auth/forgot-username', {
                method: 'POST',
                body: JSON.stringify({ email: email.trim() })
            });

            this._showMessage('success', '✅ Username Reminder Sent',
                'If an account exists, you will receive your username.');

            return { success: true };
        } catch (error) {
            console.error('🚨 Username recovery request failed:', error.name);
            this._showMessage('error', '❌ Connection Error', 'Unable to send email. Please try again.');
            return { success: false, error: 'Connection failed' };
        }
    }

    /**
     * 🔒 Get user information (server-verified)
     */
    async getUserInfo() {
        if (!this.isAuthenticated) {
            return null;
        }

        try {
            const response = await this._apiRequest('/users/me', {
                method: 'GET'
            });
            if (response?.ok) {
                const userData = await response.json();
                this.userInfo = userData;
                return userData;
            }
        } catch (error) {
            console.warn('⚠️ Failed to get user info:', error.name);
        }

        return this.userInfo;
    }

    /**
     * Setup form handlers
     */
    setupFormHandlers() {
        // Login form
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', this._handleLoginForm.bind(this));
        }

        // Register form
        const registerForm = document.getElementById('registerForm');
        if (registerForm) {
            registerForm.addEventListener('submit', this._handleRegisterForm.bind(this));
        }

        // Forgot password form
        const forgotPasswordForm = document.getElementById('forgotPasswordForm');
        if (forgotPasswordForm) {
            forgotPasswordForm.addEventListener('submit', this._handleForgotPasswordForm.bind(this));
        }

        // Forgot username form
        const forgotUsernameForm = document.getElementById('forgotUsernameForm');
        if (forgotUsernameForm) {
            forgotUsernameForm.addEventListener('submit', this._handleForgotUsernameForm.bind(this));
        }

        // Logout buttons
        document.addEventListener('click', (e) => {
            if (e.target.matches('[data-action="logout"]')) {
                e.preventDefault();
                this.logout();
            }
        });
    }

    /**
     * 🔒 Handle login form submission
     */
    async _handleLoginForm(e) {
        e.preventDefault();

        const email = document.getElementById('email')?.value?.trim();
        const password = document.getElementById('password')?.value;
        const loginBtn = document.getElementById('loginBtn');

        if (!email || !password) {
            this._showMessage('error', '⚠️ Missing Information', 'Please enter both email and password.');
            return;
        }

        this._clearMessages();
        this._setButtonLoading(loginBtn, 'Signing In...');

        try {
            await this.login(email, password);
        } finally {
            this._setButtonLoading(loginBtn, 'Sign In', false);
        }
    }

    /**
     * 🔒 Handle registration form submission
     */
    async _handleRegisterForm(e) {
        e.preventDefault();

        const formData = new FormData(e.target);
        const data = Object.fromEntries(formData);
        const registerBtn = document.getElementById('registerBtn');

        // Validation
        if (!data.email?.trim() || !data.password) {
            this._showMessage('error', '❌ Missing Information', 'Email and password are required.');
            return;
        }

        if (data.password !== data.confirmPassword) {
            this._showMessage('error', '❌ Passwords Don\'t Match', 'Please ensure both password fields are identical.');
            return;
        }

        if (!this._validatePasswordStrength(data.password)) {
            this._showMessage('error', '❌ Password Too Weak', 'Please ensure your password meets all requirements.');
            return;
        }

        this._clearMessages();
        this._setButtonLoading(registerBtn, 'Creating Account...');

        try {
            const result = await this.register({
                email: data.email.trim(),
                password: data.password,
                first_name: data.firstName?.trim() || null,
                last_name: data.lastName?.trim() || null
            });

            if (result.success) {
                e.target.reset();
            }
        } finally {
            this._setButtonLoading(registerBtn, 'Create Account', false);
        }
    }

    /**
     * Handle forgot password form
     */
    async _handleForgotPasswordForm(e) {
        e.preventDefault();

        const email = document.getElementById('email')?.value?.trim();
        const forgotBtn = document.getElementById('forgotBtn');

        if (!email) {
            this._showMessage('error', '❌ Email Required', 'Please enter your email address.');
            return;
        }

        this._clearMessages();
        this._setButtonLoading(forgotBtn, 'Sending Email...');

        try {
            await this.requestPasswordReset(email);
        } finally {
            this._setButtonLoading(forgotBtn, 'Send Reset Email', false);
        }
    }

    /**
     * Handle forgot username form
     */
    async _handleForgotUsernameForm(e) {
        e.preventDefault();

        const email = document.getElementById('email')?.value?.trim();
        const forgotBtn = document.getElementById('forgotBtn');

        if (!email) {
            this._showMessage('error', '❌ Email Required', 'Please enter your email address.');
            return;
        }

        this._clearMessages();
        this._setButtonLoading(forgotBtn, 'Sending Email...');

        try {
            await this.requestUsernameRecovery(email);
        } finally {
            this._setButtonLoading(forgotBtn, 'Send Username', false);
        }
    }

    /**
     * Setup authentication monitoring
     */
    setupAuthMonitoring() {
        // Check auth status periodically
        this.authCheckInterval = setInterval(async () => {
            const wasAuthenticated = this.isAuthenticated;
            const isNowAuthenticated = await this.checkAuthStatus();

            // Handle auth state changes
            if (wasAuthenticated && !isNowAuthenticated) {
                console.warn('🔐 Session expired');
            }
        }, 30000); // Check every 30 seconds
    }

    /**
     * Handle page access control
     */
    _handlePageAccess() {
        const currentPage = window.location.pathname;

        // Only handle redirects for specific scenarios
        if (this.isAuthenticated) {
            // If logged in and on auth pages, redirect to dashboard
            if (currentPage.includes('login.html') || currentPage.includes('register.html')) {
                this._secureRedirect('../user/dashboard.html');
            }
        } else {
            // If NOT logged in and on protected pages, redirect to login
            if (currentPage.includes('dashboard.html')) {
                this._secureRedirect('../auth/login.html');
            }
            // For register.html and login.html when not logged in: DO NOTHING (stay on page)
        }
    }

    /**
     * Setup form validation
     */
    setupValidation() {
        // Email validation
        document.addEventListener('blur', (e) => {
            if (e.target.type === 'email') {
                this._validateEmail(e.target);
            }
        }, true);

        // Password validation
        document.addEventListener('input', (e) => {
            if (e.target.id === 'password') {
                this._updatePasswordRequirements(e.target.value);
            }
            if (e.target.id === 'confirmPassword') {
                const password = document.getElementById('password')?.value || '';
                this._validatePasswordMatch(password, e.target.value, e.target);
            }
        });
    }

    /**
     * Add authentication event listener
     */
    onAuthStateChange(callback) {
        this.authEventListeners.push(callback);
    }

    /**
     * Trigger authentication events
     */
    _triggerAuthEvent(authenticated) {
        const event = new CustomEvent('authStateChange', {
            detail: { authenticated, userInfo: this.userInfo }
        });
        window.dispatchEvent(event);

        // Call registered listeners
        this.authEventListeners.forEach(callback => {
            try {
                callback(authenticated, this.userInfo);
            } catch (error) {
                console.error('🚨 Auth event listener error:', error);
            }
        });
    }

    /**
     * 🔒 Validate email format
     */
    _validateEmail(input) {
        const email = input.value?.trim();
        const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

        if (email && (!emailRegex.test(email) || email.length > 254)) {
            input.classList.add('error');
            this._showFieldError(input, 'Please enter a valid email address');
            return false;
        } else if (email) {
            input.classList.remove('error');
            input.classList.add('success');
            this._hideFieldError(input);
            return true;
        }
        return true;
    }

    /**
     * Validate password strength
     */
    _validatePasswordStrength(password) {
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

    /**
     * Update password requirements display
     */
    _updatePasswordRequirements(password) {
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

    /**
     * Validate password match
     */
    _validatePasswordMatch(password, confirmPassword, input) {
        if (confirmPassword && password !== confirmPassword) {
            input.classList.add('error');
            this._showFieldError(input, 'Passwords do not match');
            return false;
        } else if (confirmPassword) {
            input.classList.remove('error');
            input.classList.add('success');
            this._hideFieldError(input);
            return true;
        }
        return true;
    }

    /**
     * Show field error
     */
    _showFieldError(input, message) {
        this._hideFieldError(input);
        const error = document.createElement('span');
        error.className = 'field-error';
        error.textContent = String(message).substring(0, 100);
        input.parentNode.appendChild(error);
    }

    /**
     * Hide field error
     */
    _hideFieldError(input) {
        const error = input.parentNode.querySelector('.field-error');
        if (error) error.remove();
    }

    /**
     * 🔒 Show secure message
     */
    _showMessage(type, title, description = '') {
        const messageContainer = document.getElementById('message-container') ||
                                document.getElementById('messageContainer');

        if (!messageContainer) {
            if (window.displayMessage) {
                window.displayMessage(`${title}. ${description}`, type);
            }
            return;
        }

        messageContainer.innerHTML = '';

        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${type}`;

        const titleElement = document.createElement('strong');
        titleElement.textContent = String(title).substring(0, 100);
        messageDiv.appendChild(titleElement);

        if (description) {
            messageDiv.appendChild(document.createElement('br'));
            const descElement = document.createElement('span');
            descElement.textContent = String(description).substring(0, 300);
            messageDiv.appendChild(descElement);
        }

        messageContainer.appendChild(messageDiv);

        if (type === 'success') {
            setTimeout(() => {
                if (messageDiv.parentNode) {
                    messageDiv.parentNode.removeChild(messageDiv);
                }
            }, 5000);
        }
    }

    /**
     * Clear all messages
     */
    _clearMessages() {
        const messageContainer = document.getElementById('message-container') ||
                                document.getElementById('messageContainer');
        if (messageContainer) {
            messageContainer.innerHTML = '';
        }
    }

    /**
     * Set button loading state
     */
    _setButtonLoading(button, loadingText, loading = true) {
        if (!button) return;

        if (loading) {
            button.disabled = true;
            const spinner = document.createElement('span');
            spinner.className = 'loading-spinner';
            const text = document.createElement('span');
            text.textContent = String(loadingText).substring(0, 50);
            button.innerHTML = '';
            button.appendChild(spinner);
            button.appendChild(text);
        } else {
            button.disabled = false;
            button.textContent = String(loadingText).substring(0, 50);
        }
    }

    /**
     * 🔒 Secure redirect
     */
    _secureRedirect(path) {
        if (typeof path !== 'string' ||
            path.startsWith('http://') ||
            path.startsWith('https://') ||
            path.startsWith('//') ||
            path.includes('javascript:') ||
            path.includes('data:')) {
            console.error('🚨 Blocked dangerous redirect:', path);
            return;
        }

        window.location.href = path;
    }

    /**
     * Cleanup
     */
    destroy() {
        if (this.authCheckInterval) {
            clearInterval(this.authCheckInterval);
        }
        this.authEventListeners = [];
    }
}

// 🔒 Create and expose global instance
(function() {
    'use strict';

    const authInstance = new Auth();

    try {
        Object.defineProperty(window, 'Auth', {
            value: authInstance,
            writable: false,
            configurable: false
        });
    } catch (error) {
        window.Auth = authInstance;
    }
})();

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.Auth?.init();
});