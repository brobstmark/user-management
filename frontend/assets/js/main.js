/**
 * User Management System - Main JavaScript
 * Now with environment-aware configuration
 */

// Main application object
const UserManagementApp = {

    async init() {
        console.log('🚀 User Management System initializing...');

        // Initialize configuration first
        await this.initializeConfig();

        // Setup event listeners
        this.setupEventListeners();

        // Log startup info in debug mode
        window.AppConfig.debug('Application initialized successfully');
        window.AppConfig.debug('Environment:', window.AppConfig.getEnvironment());
        window.AppConfig.debug('API URL:', window.AppConfig.getApiUrl());
        window.AppConfig.debug('Features enabled:', window.AppConfig.config?.features);
    },

    async initializeConfig() {
        try {
            await window.AppConfig.init();
            console.log('✅ Configuration loaded successfully');

            // Show environment indicator in debug mode
            if (window.AppConfig.isDebug()) {
                this.addEnvironmentIndicator();
            }

        } catch (error) {
            console.error('❌ Failed to load configuration:', error);
            // App can still function with fallback config
        }
    },

    setupEventListeners() {
        // DOM loaded event
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => {
                window.AppConfig.debug('DOM loaded');
                this.onDOMReady();
            });
        } else {
            this.onDOMReady();
        }

        // Global error handling
        window.addEventListener('error', (event) => {
            window.AppConfig.debug('Global error:', event.error);
        });

        // Handle authentication token expiry
        this.setupTokenExpiryCheck();
    },

    onDOMReady() {
        // Check authentication status on protected pages
        this.checkPageAuthentication();

        // Setup navigation
        this.setupNavigation();

        // Setup form handlers if they exist
        this.setupFormHandlers();
    },

    addEnvironmentIndicator() {
        const env = window.AppConfig.getEnvironment();
        if (env !== 'production') {
            const indicator = document.createElement('div');
            indicator.style.cssText = `
                position: fixed;
                top: 0;
                right: 0;
                background: ${env === 'development' ? '#28a745' : '#ffc107'};
                color: white;
                padding: 5px 10px;
                font-size: 12px;
                font-weight: bold;
                z-index: 10000;
                text-transform: uppercase;
            `;
            indicator.textContent = env;
            document.body.appendChild(indicator);
        }
    },

    checkPageAuthentication() {
        const currentPage = window.location.pathname;
        const token = localStorage.getItem('access_token');

        // Define protected pages
        const protectedPages = [
            '/frontend/pages/user/dashboard.html',
            '/frontend/pages/user/profile.html'
        ];

        // Define auth pages (redirect if already logged in)
        const authPages = [
            '/frontend/pages/auth/login.html',
            '/frontend/pages/auth/register.html'
        ];

        if (protectedPages.some(page => currentPage.includes(page)) && !token) {
            window.AppConfig.debug('Redirecting to login - no token found');
            window.location.href = '/frontend/pages/auth/login.html';
        } else if (authPages.some(page => currentPage.includes(page)) && token) {
            // Check if token is still valid
            this.validateTokenAndRedirect();
        }
    },

    async validateTokenAndRedirect() {
        try {
            const response = await window.AppConfig.apiRequest('/users/me');
            if (response && response.ok) {
                window.AppConfig.debug('User already logged in, redirecting to dashboard');
                window.location.href = '/frontend/pages/user/dashboard.html';
            }
        } catch (error) {
            window.AppConfig.debug('Token validation failed:', error);
            // Token is invalid, remove it
            localStorage.removeItem('access_token');
            localStorage.removeItem('user_email');
        }
    },

    setupTokenExpiryCheck() {
        // Check token expiry every minute
        setInterval(() => {
            const token = localStorage.getItem('access_token');
            if (token) {
                try {
                    // Decode JWT token to check expiry (basic check)
                    const payload = JSON.parse(atob(token.split('.')[1]));
                    const now = Math.floor(Date.now() / 1000);

                    if (payload.exp && payload.exp < now) {
                        window.AppConfig.debug('Token expired, logging out');
                        this.logout();
                    }
                } catch (error) {
                    window.AppConfig.debug('Invalid token format, logging out');
                    this.logout();
                }
            }
        }, 60000); // Check every minute
    },

    setupNavigation() {
        // Add active class to current navigation item
        const currentPath = window.location.pathname;
        const navLinks = document.querySelectorAll('nav a, .nav-links a');

        navLinks.forEach(link => {
            if (link.getAttribute('href') && currentPath.includes(link.getAttribute('href'))) {
                link.classList.add('active');
            }
        });
    },

    setupFormHandlers() {
        // Basic form enhancement
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            // Add loading states to form buttons
            form.addEventListener('submit', (e) => {
                const submitBtn = form.querySelector('button[type="submit"]');
                if (submitBtn && !submitBtn.disabled) {
                    window.AppConfig.debug('Form submitted:', form.id);
                }
            });
        });
    },

    // Utility methods
    logout() {
        localStorage.removeItem('access_token');
        localStorage.removeItem('user_email');
        window.AppConfig.debug('User logged out');
        window.location.href = '/frontend/pages/auth/login.html';
    },

    async checkFeature(featureName) {
        await window.AppConfig.init(); // Ensure config is loaded
        return window.AppConfig.isFeatureEnabled(featureName);
    },

    showMessage(message, type = 'info') {
        window.AppConfig.showNotification(message, type);
    },

    // API helper methods (now using window.AppConfig)
    api: {
        async request(endpoint, options = {}) {
            return window.AppConfig.apiRequest(endpoint, options);
        },

        async get(endpoint, options = {}) {
            return this.request(endpoint, { method: 'GET', ...options });
        },

        async post(endpoint, data, options = {}) {
            return this.request(endpoint, {
                method: 'POST',
                body: JSON.stringify(data),
                ...options
            });
        },

        async put(endpoint, data, options = {}) {
            return this.request(endpoint, {
                method: 'PUT',
                body: JSON.stringify(data),
                ...options
            });
        },

        async delete(endpoint, options = {}) {
            return this.request(endpoint, { method: 'DELETE', ...options });
        }
    }
};

// Initialize the application when script loads
(async () => {
    try {
        await UserManagementApp.init();
    } catch (error) {
        console.error('Failed to initialize application:', error);
    }
})();

// Make available globally
window.UserManagementApp = UserManagementApp;