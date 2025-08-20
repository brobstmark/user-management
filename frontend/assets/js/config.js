/**
 * 🔧 Simplified Frontend Configuration System
 * ONLY handles configuration loading and environment management
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
     * 🔒 Load configuration from backend with fallback
     */
    async _loadConfig() {
        let attempt = 0;
        let lastError = null;

        while (attempt < this.maxRetries) {
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 5000);

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

                    if (this._validateConfig(rawConfig)) {
                        this.config = this._sanitizeConfig(rawConfig);
                        console.log('✅ Configuration loaded from backend');
                        break;
                    } else {
                        throw new Error('Invalid configuration format');
                    }
                } else {
                    throw new Error(`Config endpoint returned ${response.status}`);
                }
            } catch (error) {
                lastError = error;
                attempt++;
                console.warn(`⚠️ Config load attempt ${attempt}/${this.maxRetries} failed:`, error.name);

                if (attempt < this.maxRetries) {
                    await this._sleep(this.retryDelay * attempt);
                }
            }
        }

        // Use fallback if all attempts failed
        if (!this.config) {
            console.warn('⚠️ Using fallback configuration - backend unavailable');
            this.config = this._getFallbackConfig();
        }

        this.loaded = true;
        return this.config;
    }

    /**
     * 🔒 Validate configuration structure
     */
    _validateConfig(config) {
        const requiredProperties = ['api', 'app', 'features', 'security'];
        return requiredProperties.every(prop =>
            config[prop] && typeof config[prop] === 'object'
        );
    }

    /**
     * 🔒 Sanitize configuration data
     */
    _sanitizeConfig(config) {
        return {
            api: {
                baseUrl: String(config.api.baseUrl || '/api/v1').replace(/[<>"']/g, ''),
                timeout: Math.min(Math.max(parseInt(config.api.timeout) || 30000, 5000), 60000)
            },
            app: {
                name: String(config.app.name || 'User Management').substring(0, 100),
                version: String(config.app.version || '1.0.0').substring(0, 20),
                environment: ['development', 'staging', 'production'].includes(config.app.environment)
                    ? config.app.environment : 'production',
                debug: config.app.environment !== 'production' && Boolean(config.app.debug)
            },
            features: {
                emailVerification: Boolean(config.features.emailVerification),
                passwordReset: Boolean(config.features.passwordReset),
                usernameRecovery: Boolean(config.features.usernameRecovery),
                twoFactorAuth: Boolean(config.features.twoFactorAuth)
            },
            security: {
                tokenExpiry: Math.min(Math.max(parseInt(config.security.tokenExpiry) || 1800, 300), 7200),
                maxLoginAttempts: Math.min(Math.max(parseInt(config.security.maxLoginAttempts) || 5, 3), 10),
                passwordMinLength: Math.min(Math.max(parseInt(config.security.passwordMinLength) || 8, 8), 20)
            }
        };
    }

    /**
     * 🔒 Secure fallback configuration
     */
    _getFallbackConfig() {
        const hostname = window.location.hostname;
        const isLocalhost = hostname === 'localhost' || hostname === '127.0.0.1';

        return {
            api: {
                baseUrl: isLocalhost ? `${window.location.origin}/api/v1` : '/api/v1',
                timeout: 30000
            },
            app: {
                name: 'User Management System',
                version: '1.0.0',
                environment: isLocalhost ? 'development' : 'production',
                debug: isLocalhost
            },
            features: {
                emailVerification: true,
                passwordReset: true,
                usernameRecovery: true,
                twoFactorAuth: false
            },
            security: {
                tokenExpiry: 1800,
                maxLoginAttempts: 5,
                passwordMinLength: 8
            }
        };
    }

    /**
     * Get API URL with endpoint
     */
    getApiUrl(endpoint = '') {
        if (!this.loaded) {
            return `/api/v1${endpoint}`;
        }

        const sanitizedEndpoint = String(endpoint).replace(/[<>"']/g, '');
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
     * Get environment
     */
    getEnvironment() {
        return this.config?.app?.environment || 'production';
    }

    /**
     * Check if in debug mode
     */
    isDebug() {
        return this.config?.app?.debug || false;
    }

    /**
     * Get app info
     */
    getAppInfo() {
        return {
            name: this.config?.app?.name || 'User Management System',
            version: this.config?.app?.version || '1.0.0',
            environment: this.getEnvironment()
        };
    }

    /**
     * Sleep utility for retry logic
     */
    _sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, Math.min(ms, 5000)));
    }
}

// 🔒 Create and expose global instance
(function() {
    'use strict';

    const appConfigInstance = new AppConfig();

    try {
        Object.defineProperty(window, 'AppConfig', {
            value: appConfigInstance,
            writable: false,
            configurable: false
        });
    } catch (error) {
        window.AppConfig = appConfigInstance;
    }
})();