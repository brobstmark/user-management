/**
 * Clean Authentication System
 * Responsibilities: API calls, session management, authentication state
 * Does NOT handle: Form validation, UI state, button management
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
        this.setupEventHandlers();

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

        console.log('Authentication system initialized');
    }

    /**
     * Initialize CSRF protection
     */
    async initCSRF() {
        try {
            const url = window.AppConfig?.getApiUrl('/auth/csrf-token') || '/api/v1/auth/csrf-token';
            const response = await fetch(url, {
                method: 'GET',
                credentials: 'include'
            });

            if (response.ok) {
                const data = await response.json();
                this.csrfToken = data.csrf_token;
                console.log('CSRF token initialized');
            }
        } catch (error) {
            console.warn('Failed to initialize CSRF token:', error.name);
        }
    }

    /**
     * Make API request with proper cookie handling
     */
    async _apiRequest(endpoint, options = {}) {
        const url = window.AppConfig?.getApiUrl(endpoint) || `/api/v1${endpoint}`;

        const config = {
            credentials: 'include',
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
            if (response.ok) {
                const responseClone = response.clone();
                const debugData = await responseClone.json();
            }
            // Handle auth errors - only redirect from protected pages
            if (response.status === 401) {
                this.isAuthenticated = false;
                this.userInfo = null;
                this._triggerAuthEvent(false);

                const currentPage = window.location.pathname;
                if (currentPage.includes('dashboard.html') && !currentPage.includes('login.html') && !currentPage.includes('register.html')) {
                    this._secureRedirect('../auth/login.html');
                }
                return null;
            }

            return response;
        } catch (error) {
            console.error('API request failed:', error.name);
            throw error;
        }
    }

    /**
     * Quick auth check for public pages (no redirects)
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
     * Check authentication status (server-side verification)
     */
    async checkAuthStatus() {
        try {
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
            console.warn('Auth status check failed:', error.name);
            this.isAuthenticated = false;
            this.userInfo = null;
            this._triggerAuthEvent(false);
            this._handlePageAccess();
            return false;
        }
    }

    /**
     * PUBLIC API: Login user (called by login.js)
     * Returns: {success: boolean, error?: string}
     */
    async login(email, password) {
        try {
            // Check for return_url parameter
            const urlParams = new URLSearchParams(window.location.search);
            const returnUrl = urlParams.get('return_url');

            // Prepare request body
            const requestBody = {
                email: email.trim(),
                password: password
            };

            // Build the endpoint URL with return_url as query parameter
            let endpoint = '/auth/login';
            if (returnUrl) {
                endpoint += `?return_url=${encodeURIComponent(returnUrl)}`;
            }

            const response = await this._apiRequest(endpoint, {
                method: 'POST',
                body: JSON.stringify(requestBody)
            });

            if (response?.ok) {
                const responseData = await response.json();


                // Handle redirect immediately - don't use setTimeout
                if (responseData.return_url) {
                    // Redirect immediately to return URL
                    window.location.href = responseData.return_url;
                } else {
                    // Only refresh auth state if going to dashboard
                    await this.checkAuthStatus();
                    setTimeout(() => {
                        this._secureRedirect('../user/dashboard.html');
                    }, 1500);
                }

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

                return { success: false, error: errorMessage };
            }
        } catch (error) {
            console.error('Login request failed:', error.name);
            return { success: false, error: 'Connection failed' };
        }
    }

    /**
     * PUBLIC API: Register user
     */
    async register(userData) {
        try {
            const response = await this._apiRequest('/auth/register', {
                method: 'POST',
                body: JSON.stringify(userData)
            });

            if (response?.ok) {
                console.log('Registration successful');

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

                return { success: false, error: errorMessage };
            }
        } catch (error) {
            console.error('Registration failed:', error.name);
            return { success: false, error: 'Connection failed' };
        }
    }

    /**
     * PUBLIC API: Logout user
     */
    async logout() {
        try {
            await this._apiRequest('/auth/logout', {
                method: 'POST'
            });
        } catch (error) {
            console.warn('Logout request failed:', error.name);
        } finally {
            // Clear local state regardless of server response
            this.isAuthenticated = false;
            this.userInfo = null;
            this._triggerAuthEvent(false);

            console.log('Logged out');
            this._secureRedirect('../auth/login.html');
        }
    }

    /**
     * PUBLIC API: Request password reset
     */
    async requestPasswordReset(email) {
        try {
            const response = await this._apiRequest('/auth/forgot-password', {
                method: 'POST',
                body: JSON.stringify({ email: email.trim() })
            });

            if (response?.ok) {
                return { success: true };
            } else {
                let errorMessage = 'Unable to send email. Please try again.';
                switch (response?.status) {
                    case 429:
                        errorMessage = 'Too many requests. Please try again later.';
                        break;
                    case 500:
                        errorMessage = 'Server temporarily unavailable. Please try again later.';
                        break;
                }
                return { success: false, error: errorMessage };
            }
        } catch (error) {
            return { success: false, error: 'Connection failed' };
        }
    }

    /**
     * PUBLIC API: Get user information
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
            console.warn('Failed to get user info:', error.name);
        }

        return this.userInfo;
    }

    /**
     * Setup event handlers (NO form handling - that's login.js responsibility)
     */
    setupEventHandlers() {
        // Only handle logout buttons - forms are handled by their respective UI files
        document.addEventListener('click', (e) => {
            if (e.target.matches('[data-action="logout"]')) {
                e.preventDefault();
                this.logout();
            }
        });
    }

    /**
     * Setup authentication monitoring
     */
    setupAuthMonitoring() {
        this.authCheckInterval = setInterval(async () => {
            const wasAuthenticated = this.isAuthenticated;
            const isNowAuthenticated = await this.checkAuthStatus();

            if (wasAuthenticated && !isNowAuthenticated) {
                console.warn('Session expired');
            }
        }, 30000);
    }

    /**
     * Handle page access control
     */
    _handlePageAccess() {
        const currentPage = window.location.pathname;

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
        }
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

        this.authEventListeners.forEach(callback => {
            try {
                callback(authenticated, this.userInfo);
            } catch (error) {
                console.error('Auth event listener error:', error);
            }
        });
    }

    /**
     * Secure redirect
     */
    _secureRedirect(path) {
        if (typeof path !== 'string' ||
            path.startsWith('http://') ||
            path.startsWith('https://') ||
            path.startsWith('//') ||
            path.includes('javascript:') ||
            path.includes('data:')) {
            console.error('Blocked dangerous redirect:', path);
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

// Create and expose global instance
(function() {
    'use strict';

    const authInstance = new Auth();

    // Expose clean public API
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