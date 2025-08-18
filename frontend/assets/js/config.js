/**
 * Secure Frontend Configuration System
 * Dynamically loads configuration from backend with security protections
 */

class AppConfig {
    constructor() {
        this.config = null;
        this.loaded = false;
        this.loadPromise = null;
        this.maxRetries = 3;
        this.retryDelay = 1000;
    }

    /**
     * Initialize and load configuration
     */
    async init() {
        if (this.loadPromise) {
            return this.loadPromise;
        }

        this.loadPromise = this._loadConfig();
        return this.loadPromise;
    }

    /**
     * 🔒 Secure configuration loading with validation
     */
    async _loadConfig() {
        let attempt = 0;
        let lastError = null;

        while (attempt < this.maxRetries) {
            try {
                // 🔒 Secure fetch with timeout
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout

                const response = await fetch('/api/config', {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                        'Cache-Control': 'no-cache'
                    },
                    signal: controller.signal
                });

                clearTimeout(timeoutId);

                if (response.ok) {
                    const rawConfig = await response.json();

                    // 🔒 Validate configuration before use
                    if (this._validateConfig(rawConfig)) {
                        this.config = this._sanitizeConfig(rawConfig);

                        // 🔒 Log success without exposing sensitive data
                        if (window.logInfo) {
                            window.logInfo('Configuration loaded successfully', {
                                source: 'backend',
                                environment: this.config.app?.environment || 'unknown'
                            });
                        }

                        break;
                    } else {
                        throw new Error('Invalid configuration format received');
                    }
                } else {
                    throw new Error(`Config endpoint returned ${response.status}`);
                }
            } catch (error) {
                lastError = error;
                attempt++;

                // 🔒 Log attempt without exposing sensitive details
                if (window.logWarn) {
                    window.logWarn('Configuration load attempt failed', {
                        attempt: attempt,
                        max_attempts: this.maxRetries,
                        error_type: error.name
                    });
                }

                if (attempt < this.maxRetries) {
                    await this._sleep(this.retryDelay * attempt);
                }
            }
        }

        // If all attempts failed, use fallback
        if (!this.config) {
            if (window.logWarn) {
                window.logWarn('Using fallback configuration', {
                    reason: 'backend_unavailable',
                    last_error: lastError?.name
                });
            }

            this.config = this._getFallbackConfig();
        }

        this.loaded = true;
        this._setGlobalStyles();
        return this.config;
    }

    /**
     * 🔒 Validate configuration structure
     */
    _validateConfig(config) {
        try {
            // Check required top-level properties
            const requiredProperties = ['api', 'app', 'features', 'security', 'ui'];
            for (const prop of requiredProperties) {
                if (!config[prop] || typeof config[prop] !== 'object') {
                    return false;
                }
            }

            // Validate API configuration
            if (!config.api.baseUrl || typeof config.api.baseUrl !== 'string') {
                return false;
            }

            // Validate app configuration
            if (!config.app.environment || !config.app.name) {
                return false;
            }

            // Validate environment value
            const validEnvironments = ['development', 'staging', 'production'];
            if (!validEnvironments.includes(config.app.environment)) {
                return false;
            }

            return true;
        } catch (error) {
            return false;
        }
    }

    /**
     * 🔒 Sanitize configuration data
     */
    _sanitizeConfig(config) {
        return {
            api: {
                baseUrl: String(config.api.baseUrl).replace(/[<>"']/g, ''), // Remove dangerous chars
                timeout: Math.min(Math.max(parseInt(config.api.timeout) || 30000, 5000), 60000), // 5-60 seconds
                retries: Math.min(Math.max(parseInt(config.api.retries) || 3, 1), 5) // 1-5 retries
            },
            app: {
                name: String(config.app.name).substring(0, 100), // Limit length
                version: String(config.app.version || '1.0.0').substring(0, 20),
                environment: ['development', 'staging', 'production'].includes(config.app.environment)
                    ? config.app.environment : 'production',
                debug: config.app.environment !== 'production' && Boolean(config.app.debug)
            },
            features: {
                emailVerification: Boolean(config.features.emailVerification),
                passwordReset: Boolean(config.features.passwordReset),
                usernameRecovery: Boolean(config.features.usernameRecovery),
                twoFactorAuth: Boolean(config.features.twoFactorAuth),
                socialAuth: Boolean(config.features.socialAuth)
            },
            security: {
                tokenExpiry: Math.min(Math.max(parseInt(config.security.tokenExpiry) || 1800, 300), 7200), // 5min-2hrs
                maxLoginAttempts: Math.min(Math.max(parseInt(config.security.maxLoginAttempts) || 5, 3), 10), // 3-10
                passwordMinLength: Math.min(Math.max(parseInt(config.security.passwordMinLength) || 8, 8), 20) // 8-20
            },
            ui: {
                theme: ['light', 'dark'].includes(config.ui.theme) ? config.ui.theme : 'light',
                showDebugInfo: config.app.environment !== 'production' && Boolean(config.ui.showDebugInfo),
                enableAnalytics: config.app.environment === 'production' && Boolean(config.ui.enableAnalytics)
            }
        };
    }

    /**
     * 🔒 Secure fallback configuration
     */
    _getFallbackConfig() {
        const hostname = window.location.hostname;
        const protocol = window.location.protocol;
        const port = window.location.port;

        // 🔒 Secure environment detection
        let environment = 'production';
        let debug = false;
        let apiBaseUrl = '/api/v1';

        // Only allow localhost/127.0.0.1 for development
        if (hostname === 'localhost' || hostname === '127.0.0.1') {
            environment = 'development';
            debug = true;
            // 🔒 Validate protocol and port for security
            if (protocol === 'http:' || protocol === 'https:') {
                const safePort = port && /^\d{1,5}$/.test(port) ? port : '8000';
                apiBaseUrl = `${protocol}//${hostname}:${safePort}/api/v1`;
            }
        } else if (hostname.includes('staging') || hostname.includes('dev')) {
            environment = 'staging';
            debug = false; // Don't enable debug in staging by default
        }

        return {
            api: {
                baseUrl: apiBaseUrl,
                timeout: 30000,
                retries: 3
            },
            app: {
                name: 'User Management System',
                version: '1.0.0',
                environment: environment,
                debug: debug
            },
            features: {
                emailVerification: true,
                passwordReset: true,
                usernameRecovery: true,
                twoFactorAuth: false,
                socialAuth: false
            },
            security: {
                tokenExpiry: 1800, // 30 minutes in seconds
                maxLoginAttempts: 5,
                passwordMinLength: 8
            },
            ui: {
                theme: 'light',
                showDebugInfo: debug,
                enableAnalytics: environment === 'production'
            }
        };
    }

    /**
     * 🔒 Secure CSS styling with validation
     */
    _setGlobalStyles() {
        try {
            const root = document.documentElement;

            // 🔒 Validate theme value before applying
            const theme = this.config.ui.theme;
            if (!['light', 'dark'].includes(theme)) {
                if (window.logWarn) {
                    window.logWarn('Invalid theme value, using default', { theme });
                }
                return;
            }

            // 🔒 Secure CSS property setting
            const cssProperties = theme === 'dark' ? {
                '--primary-color': '#667eea',
                '--background-color': '#1a1a1a',
                '--text-color': '#ffffff'
            } : {
                '--primary-color': '#667eea',
                '--background-color': '#ffffff',
                '--text-color': '#333333'
            };

            // Apply CSS properties safely
            for (const [property, value] of Object.entries(cssProperties)) {
                // 🔒 Validate CSS property name and value
                if (/^--[a-z-]+$/.test(property) && /^[#a-zA-Z0-9\s]+$/.test(value)) {
                    root.style.setProperty(property, value);
                }
            }

            // 🔒 Safe debug mode indication
            if (this.config.ui.showDebugInfo) {
                document.body.classList.add('debug-mode');
            }
        } catch (error) {
            if (window.logError) {
                window.logError('Failed to set global styles', {
                    error_type: error.name
                });
            }
        }
    }

    /**
     * 🔒 Secure API URL generation
     */
    getApiUrl(endpoint = '') {
        if (!this.loaded) {
            // Use safe fallback
            return `/api/v1${endpoint}`;
        }

        // 🔒 Validate endpoint parameter
        if (typeof endpoint !== 'string') {
            endpoint = '';
        }

        // 🔒 Sanitize endpoint to prevent injection
        const sanitizedEndpoint = endpoint.replace(/[<>"']/g, '');

        return `${this.config.api.baseUrl}${sanitizedEndpoint}`;
    }

    /**
     * Get feature flag status
     */
    isFeatureEnabled(feature) {
        return this.config?.features?.[feature] || false;
    }

    /**
     * Get security setting
     */
    getSecuritySetting(setting) {
        return this.config?.security?.[setting];
    }

    /**
     * Get app information (safe subset)
     */
    getAppInfo() {
        const appInfo = this.config?.app || {};
        // 🔒 Return only safe properties
        return {
            name: appInfo.name,
            version: appInfo.version,
            environment: appInfo.environment
        };
    }

    /**
     * Check if in debug mode
     */
    isDebug() {
        return this.config?.app?.debug || false;
    }

    /**
     * Get environment
     */
    getEnvironment() {
        return this.config?.app?.environment || 'production';
    }

    /**
     * 🔒 Secure debug logging
     */
    debug(...args) {
        if (this.isDebug() && window.logDebug) {
            // 🔒 Use secure logger instead of console.log
            window.logDebug('AppConfig debug', {
                environment: this.getEnvironment(),
                data: args
            });
        }
    }

    /**
     * 🔒 Secure token retrieval (consistent with auth.js)
     */
    _getToken() {
        try {
            // 🔒 Use sessionStorage for consistency with auth.js
            return sessionStorage.getItem('access_token');
        } catch (error) {
            if (window.logError) {
                window.logError('Failed to retrieve token', {
                    error_type: error.name
                });
            }
            return null;
        }
    }

    /**
     * 🔒 Secure redirect function
     */
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

        window.location.href = path;
    }

    /**
     * 🔒 Secure API request with enhanced security
     */
    async apiRequest(endpoint, options = {}) {
        if (!this.loaded) {
            await this.init();
        }

        const token = this._getToken();
        const url = this.getApiUrl(endpoint);

        // 🔒 Validate URL before making request
        try {
            new URL(url, window.location.origin);
        } catch (error) {
            if (window.logSecurityEvent) {
                window.logSecurityEvent('invalid_api_url', {
                    endpoint,
                    error_type: error.name
                });
            }
            throw new Error('Invalid API URL');
        }

        const config = {
            headers: {
                'Content-Type': 'application/json',
                ...(token && { 'Authorization': `Bearer ${token}` }),
                ...options.headers,
            },
            ...options,
        };

        try {
            const response = await fetch(url, config);

            // 🔒 Handle authentication errors securely
            if (response.status === 401) {
                // 🔒 Clear tokens securely
                try {
                    sessionStorage.removeItem('access_token');
                    sessionStorage.removeItem('user_email');
                } catch (error) {
                    // Handle storage errors gracefully
                }

                // 🔒 Log security event
                if (window.logSecurityEvent) {
                    window.logSecurityEvent('authentication_expired', {
                        action: 'token_invalid',
                        endpoint: endpoint
                    });
                }

                // 🔒 Secure redirect to login
                if (!window.location.pathname.includes('login.html')) {
                    this._secureRedirect('/frontend/pages/auth/login.html');
                }
                return null;
            }

            return response;
        } catch (error) {
            // 🔒 Secure error logging
            if (window.logError) {
                window.logError('API request failed', {
                    endpoint: endpoint,
                    error_type: error.name,
                    status: error.status || 'network_error'
                });
            }
            throw error;
        }
    }

    /**
     * 🔒 Secure notification system
     */
    showNotification(message, type = 'info') {
        // 🔒 Sanitize message
        const sanitizedMessage = String(message).substring(0, 200);
        const sanitizedType = ['info', 'success', 'warning', 'error'].includes(type) ? type : 'info';

        if (window.logInfo) {
            window.logInfo('Notification displayed', {
                type: sanitizedType,
                message: sanitizedMessage
            });
        }

        // Use global message display if available
        if (window.displayMessage) {
            window.displayMessage(sanitizedMessage, sanitizedType);
        }
    }

    /**
     * 🔒 Sleep utility for retry logic
     */
    _sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, Math.min(ms, 5000))); // Max 5 second delay
    }
}

// 🔒 Secure global instance creation
(function() {
    'use strict';

    try {
        const appConfigInstance = new AppConfig();

        // 🔒 Secure global exposure with protection
        Object.defineProperty(window, 'AppConfig', {
            value: appConfigInstance,
            writable: false,
            configurable: false
        });

        // 🔒 Log initialization securely
        if (window.logInfo) {
            window.logInfo('AppConfig initialized', {
                module: 'config'
            });
        }
    } catch (error) {
        // 🔒 Fallback if defineProperty fails
        window.AppConfig = new AppConfig();

        if (window.logError) {
            window.logError('AppConfig initialization fallback used', {
                error_type: error.name
            });
        }
    }
})();