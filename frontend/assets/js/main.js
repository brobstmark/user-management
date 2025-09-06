/**
 * Secure User Management System - Main JavaScript
 * Enhanced with comprehensive security and logging integration
 */

// 🔒 Secure main application object
const UserManagementApp = {

    // Application state
    _initialized: false,
    _timers: [],

    async init() {
        if (this._initialized) {
            return;
        }

        try {
            // 🔒 Log initialization start
            if (window.logInfo) {
                window.logInfo('Application initializing', {
                    module: 'main',
                    url: window.location.href
                });
            }

            // Initialize configuration first
            await this.initializeConfig();

            // Setup event listeners
            this.setupEventListeners();

            // Setup security monitoring
            this.setupSecurityMonitoring();

            this._initialized = true;

            // 🔒 Log successful initialization
            if (window.logInfo) {
                window.logInfo('Application initialized successfully', {
                    module: 'main',
                    environment: window.AppConfig?.getEnvironment() || 'unknown'
                });
            }

        } catch (error) {
            // 🔒 Log initialization failure
            if (window.logError) {
                window.logError('Application initialization failed', {
                    module: 'main',
                    error_type: error.name,
                    error_message: error.message
                });
            }
            throw error;
        }
    },

    async initializeConfig() {
        try {
            if (!window.AppConfig) {
                throw new Error('AppConfig not available');
            }

            await window.AppConfig.init();

            // 🔒 Show environment indicator in non-production only
            if (window.AppConfig.isDebug()) {
                this.addEnvironmentIndicator();
            }

            // 🔒 Log configuration success
            if (window.logInfo) {
                window.logInfo('Configuration loaded successfully', {
                    module: 'main',
                    environment: window.AppConfig.getEnvironment()
                });
            }

        } catch (error) {
            // 🔒 Log configuration failure
            if (window.logError) {
                window.logError('Configuration loading failed', {
                    module: 'main',
                    error_type: error.name
                });
            }
            throw error;
        }
    },

    setupEventListeners() {
        // DOM ready handling
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => {
                this.onDOMReady();
            });
        } else {
            this.onDOMReady();
        }

        // 🔒 Secure global error handling
        window.addEventListener('error', (event) => {
            this.handleGlobalError(event);
        });

        // 🔒 Handle unhandled promise rejections
        window.addEventListener('unhandledrejection', (event) => {
            this.handleUnhandledRejection(event);
        });

        // 🔒 Setup secure token management
        this.setupTokenManagement();

        // 🔒 Setup page visibility monitoring
        this.setupVisibilityMonitoring();
    },

    onDOMReady() {
        // 🔒 Log DOM ready
        if (window.logInfo) {
            window.logInfo('DOM ready', {
                module: 'main',
                page: window.location.pathname.split('/').pop()
            });
        }

        // Check authentication status on protected pages
        this.checkPageAuthentication();

        // Setup navigation
        this.setupNavigation();

        // Setup form handlers
        this.setupFormHandlers();

        // Setup security features
        this.setupPageSecurity();
    },

    addEnvironmentIndicator() {
        const env = window.AppConfig.getEnvironment();
        if (env !== 'production') {
            const indicator = document.createElement('div');

            // 🔒 Secure styling without CSS injection
            const styles = {
                position: 'fixed',
                top: '0',
                right: '0',
                background: env === 'development' ? '#28a745' : '#ffc107',
                color: 'white',
                padding: '5px 10px',
                fontSize: '12px',
                fontWeight: 'bold',
                zIndex: '10000',
                textTransform: 'uppercase',
                borderBottomLeftRadius: '4px'
            };

            Object.assign(indicator.style, styles);
            indicator.textContent = env; // 🔒 Use textContent to prevent XSS
            document.body.appendChild(indicator);

            // 🔒 Log environment indicator display
            if (window.logInfo) {
                window.logInfo('Environment indicator displayed', {
                    environment: env
                });
            }
        }
    },

    checkPageAuthentication() {
        const currentPage = window.location.pathname;
        const token = this._getToken();

        // 🔒 Define protected pages with validation
        const protectedPages = [
            '/frontend/pages/user/dashboard.html',
            '/frontend/pages/user/profile.html',
            '/frontend/pages/admin/'
        ];

        // 🔒 Define auth pages
        const authPages = [
            '/frontend/pages/auth/login.html',
            '/frontend/pages/auth/register.html',
            '/frontend/pages/auth/forgot-password.html',
            '/frontend/pages/auth/forgot-username.html'
        ];

        // 🔒 Log authentication check
        if (window.logInfo) {
            window.logInfo('Checking page authentication', {
                page: currentPage,
                has_token: !!token,
                is_protected: protectedPages.some(page => currentPage.includes(page)),
                is_auth_page: authPages.some(page => currentPage.includes(page))
            });
        }

        if (protectedPages.some(page => currentPage.includes(page)) && !token) {
            // 🔒 Log unauthorized access attempt
            if (window.logSecurityEvent) {
                window.logSecurityEvent('unauthorized_access_attempt', {
                    attempted_page: currentPage,
                    reason: 'no_token'
                });
            }

            this._secureRedirect('/frontend/pages/auth/login.html');
        } else if (authPages.some(page => currentPage.includes(page)) && token) {
            // Check if token is still valid
            this.validateTokenAndRedirect();
        }
    },

    async validateTokenAndRedirect() {
        try {
            const response = await window.AppConfig.apiRequest('/users/me');
            if (response && response.ok) {
                // 🔒 Log already authenticated user
                if (window.logInfo) {
                    window.logInfo('User already authenticated, redirecting', {
                        action: 'redirect_to_dashboard'
                    });
                }

                this._secureRedirect('/frontend/pages/user/dashboard.html');
            }
        } catch (error) {
            // 🔒 Log token validation failure
            if (window.logSecurityEvent) {
                window.logSecurityEvent('token_validation_failed', {
                    action: 'token_invalid',
                    error_type: error.name
                });
            }

            // Token is invalid, remove it
            this._removeToken();
        }
    },

    setupTokenManagement() {
        // 🔒 Secure token expiry check using API validation instead of JWT parsing
        const timerId = setInterval(async () => {
            const token = this._getToken();
            if (token) {
                try {
                    // 🔒 Validate token with backend instead of parsing JWT
                    const response = await window.AppConfig.apiRequest('/users/me');
                    if (!response || !response.ok) {
                        // Token is invalid
                        if (window.logSecurityEvent) {
                            window.logSecurityEvent('token_expired_or_invalid', {
                                action: 'auto_logout',
                                status: response?.status || 'network_error'
                            });
                        }
                        this.logout();
                    }
                } catch (error) {
                    // Network error or other issues - don't automatically logout
                    if (window.logWarn) {
                        window.logWarn('Token validation check failed', {
                            error_type: error.name,
                            action: 'skip_auto_logout'
                        });
                    }
                }
            }
        }, 300000); // Check every 5 minutes (less frequent, more efficient)

        this._timers.push(timerId);
    },

    setupVisibilityMonitoring() {
        // 🔒 Monitor page visibility for security
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                // 🔒 Log when user navigates away
                if (window.logInfo) {
                    window.logInfo('Page became hidden', {
                        action: 'page_hidden'
                    });
                }
            } else {
                // 🔒 Log when user returns
                if (window.logInfo) {
                    window.logInfo('Page became visible', {
                        action: 'page_visible'
                    });
                }

                // Re-validate token when user returns
                if (this._getToken()) {
                    this.validateTokenAndRedirect();
                }
            }
        });
    },

    setupNavigation() {
        // 🔒 Secure navigation setup
        const currentPath = window.location.pathname;
        const navLinks = document.querySelectorAll('nav a, .nav-links a');

        navLinks.forEach(link => {
            const href = link.getAttribute('href');
            if (href && this._isValidInternalLink(href) && currentPath.includes(href)) {
                link.classList.add('active');
            }

            // 🔒 Add click monitoring for navigation
            link.addEventListener('click', (e) => {
                const destination = link.getAttribute('href');
                if (window.logInfo) {
                    window.logInfo('Navigation link clicked', {
                        destination: destination,
                        current_page: currentPath
                    });
                }
            });
        });
    },

    setupFormHandlers() {
        // 🔒 Secure form enhancement
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            form.addEventListener('submit', (e) => {
                const submitBtn = form.querySelector('button[type="submit"]');
                if (submitBtn && !submitBtn.disabled) {
                    // 🔒 Log form submission
                    if (window.logInfo) {
                        window.logInfo('Form submitted', {
                            form_id: form.id || 'unnamed',
                            action: form.action || 'javascript',
                            method: form.method || 'get'
                        });
                    }
                }
            });

            // 🔒 Monitor for rapid form submissions (potential attack)
            let lastSubmit = 0;
            form.addEventListener('submit', (e) => {
                const now = Date.now();
                if (now - lastSubmit < 1000) { // Less than 1 second
                    if (window.logSecurityEvent) {
                        window.logSecurityEvent('rapid_form_submission', {
                            form_id: form.id || 'unnamed',
                            time_between_submits: now - lastSubmit
                        });
                    }
                }
                lastSubmit = now;
            });
        });
    },

    setupPageSecurity() {
        // 🔒 Setup security monitoring for the page
        this.monitorSuspiciousActivity();
        this.setupCSRFProtection();
    },

    monitorSuspiciousActivity() {
        // 🔒 Monitor for suspicious JavaScript activity
        let rapidClicks = 0;
        let lastClick = 0;

        document.addEventListener('click', (e) => {
            const now = Date.now();
            if (now - lastClick < 100) { // Very rapid clicking
                rapidClicks++;
                if (rapidClicks > 10 && window.logSecurityEvent) {
                    window.logSecurityEvent('suspicious_rapid_clicking', {
                        click_count: rapidClicks,
                        target: e.target.tagName
                    });
                }
            } else {
                rapidClicks = 0;
            }
            lastClick = now;
        });
    },

    setupCSRFProtection() {
        // 🔒 Add CSRF token to forms if available
        const csrfToken = document.querySelector('meta[name="csrf-token"]');
        if (csrfToken) {
            const forms = document.querySelectorAll('form');
            forms.forEach(form => {
                if (!form.querySelector('input[name="csrf_token"]')) {
                    const input = document.createElement('input');
                    input.type = 'hidden';
                    input.name = 'csrf_token';
                    input.value = csrfToken.getAttribute('content');
                    form.appendChild(input);
                }
            });
        }
    },

    setupSecurityMonitoring() {
        // 🔒 Monitor for security-related browser events
        window.addEventListener('beforeunload', () => {
            if (window.logInfo) {
                window.logInfo('Page unloading', {
                    action: 'page_unload'
                });
            }
        });

        // 🔒 Monitor for developer tools opening (basic detection)
        let devtools = {open: false, orientation: null};
        setInterval(() => {
            if (window.outerHeight - window.innerHeight > 200 ||
                window.outerWidth - window.innerWidth > 200) {
                if (!devtools.open && window.logSecurityEvent) {
                    window.logSecurityEvent('developer_tools_opened', {
                        action: 'devtools_detected'
                    });
                }
                devtools.open = true;
            } else {
                devtools.open = false;
            }
        }, 500);
    },

    // 🔒 Secure token management methods
    _getToken() {
        try {
            return sessionStorage.getItem('access_token');
        } catch (error) {
            if (window.logError) {
                window.logError('Failed to retrieve token', {
                    error_type: error.name
                });
            }
            return null;
        }
    },

    _removeToken() {
        try {
            sessionStorage.removeItem('access_token');
            sessionStorage.removeItem('user_email');

            if (window.logAuthEvent) {
                window.logAuthEvent('token_removed', {
                    action: 'token_cleanup'
                });
            }
        } catch (error) {
            if (window.logError) {
                window.logError('Failed to remove token', {
                    error_type: error.name
                });
            }
        }
    },

    // 🔒 Secure redirect function
    _secureRedirect(path) {
        // 🔒 Validate redirect path
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

    // 🔒 Validate internal links
    _isValidInternalLink(href) {
        return href &&
               !href.startsWith('http://') &&
               !href.startsWith('https://') &&
               !href.startsWith('//') &&
               !href.includes('javascript:') &&
               !href.includes('data:');
    },

    // 🔒 Secure error handlers
    handleGlobalError(event) {
        if (window.logError) {
            window.logError('Global JavaScript error', {
                message: event.message,
                filename: event.filename,
                lineno: event.lineno,
                colno: event.colno,
                error_type: 'javascript_error'
            });
        }
    },

    handleUnhandledRejection(event) {
        if (window.logError) {
            window.logError('Unhandled promise rejection', {
                reason: event.reason?.toString()?.substring(0, 500),
                error_type: 'promise_rejection'
            });
        }
    },

    // Public utility methods
    logout() {
        // 🔒 Log logout attempt
        if (window.logAuthEvent) {
            window.logAuthEvent('logout_initiated', {
                action: 'manual_logout'
            });
        }

        this._removeToken();
        this._secureRedirect('/frontend/pages/auth/login.html');
    },

    async checkFeature(featureName) {
        try {
            await window.AppConfig.init();
            return window.AppConfig.isFeatureEnabled(featureName);
        } catch (error) {
            if (window.logError) {
                window.logError('Feature check failed', {
                    feature: featureName,
                    error_type: error.name
                });
            }
            return false;
        }
    },

    showMessage(message, type = 'info') {
        // 🔒 Sanitize message before display
        const sanitizedMessage = String(message).substring(0, 200);
        const sanitizedType = ['info', 'success', 'warning', 'error'].includes(type) ? type : 'info';

        if (window.AppConfig) {
            window.AppConfig.showNotification(sanitizedMessage, sanitizedType);
        } else if (window.displayMessage) {
            window.displayMessage(sanitizedMessage, sanitizedType);
        }
    },

    // 🔒 Secure API helper methods
    api: {
        async request(endpoint, options = {}) {
            if (!window.AppConfig) {
                throw new Error('AppConfig not available');
            }
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
    },

    // 🔒 Cleanup method
    destroy() {
        // Clear all timers
        this._timers.forEach(timerId => clearInterval(timerId));
        this._timers = [];

        if (window.logInfo) {
            window.logInfo('Application destroyed', {
                module: 'main'
            });
        }
    }
};

// 🔒 Secure initialization with error handling
(async () => {
    try {
        await UserManagementApp.init();
    } catch (error) {
        // 🔒 Log critical initialization failure
        if (window.logError) {
            window.logError('Critical application initialization failure', {
                error_type: error.name,
                error_message: error.message
            });
        } else {
            console.error('Failed to initialize application:', error);
        }
    }
})();

// 🔒 Secure global exposure with protection
try {
    Object.defineProperty(window, 'UserManagementApp', {
        value: UserManagementApp,
        writable: false,
        configurable: false
    });
} catch (error) {
    // Fallback if defineProperty fails
    window.UserManagementApp = UserManagementApp;
}

// 🔒 Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (UserManagementApp.destroy) {
        UserManagementApp.destroy();
    }
});