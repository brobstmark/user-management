/**
 * Frontend Configuration System
 * Dynamically loads configuration from backend or detects environment
 */

class AppConfig {
    constructor() {
        this.config = null;
        this.loaded = false;
        this.loadPromise = null;
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
     * Load configuration from backend or use fallback
     */
    async _loadConfig() {
        try {
            // Try to load config from backend
            const response = await fetch('/api/config', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            if (response.ok) {
                this.config = await response.json();
                console.log('✅ Configuration loaded from backend:', this.config.app.environment);
            } else {
                throw new Error(`Config endpoint returned ${response.status}`);
            }
        } catch (error) {
            console.warn('⚠️ Failed to load config from backend, using fallback:', error.message);
            this.config = this._getFallbackConfig();
        }

        this.loaded = true;

        // Set global CSS variables based on config
        this._setGlobalStyles();

        return this.config;
    }

    /**
     * Get fallback configuration (environment detection)
     */
    _getFallbackConfig() {
        const hostname = window.location.hostname;
        const protocol = window.location.protocol;
        const port = window.location.port;

        // Detect environment
        let environment = 'production';
        let debug = false;
        let apiBaseUrl = '/api/v1';

        if (hostname === 'localhost' || hostname === '127.0.0.1') {
            environment = 'development';
            debug = true;
            apiBaseUrl = `${protocol}//${hostname}:${port || '8000'}/api/v1`;
        } else if (hostname.includes('staging') || hostname.includes('dev')) {
            environment = 'staging';
            debug = true;
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
     * Set global CSS variables based on configuration
     */
    _setGlobalStyles() {
        const root = document.documentElement;

        // Set CSS variables for theming
        if (this.config.ui.theme === 'dark') {
            root.style.setProperty('--primary-color', '#667eea');
            root.style.setProperty('--background-color', '#1a1a1a');
            root.style.setProperty('--text-color', '#ffffff');
        } else {
            root.style.setProperty('--primary-color', '#667eea');
            root.style.setProperty('--background-color', '#ffffff');
            root.style.setProperty('--text-color', '#333333');
        }

        // Add debug styles if enabled
        if (this.config.ui.showDebugInfo) {
            document.body.classList.add('debug-mode');
        }
    }

    /**
     * Get API base URL
     */
    getApiUrl(endpoint = '') {
        if (!this.loaded) {
            console.warn('Config not loaded yet, using fallback API URL');
            return `/api/v1${endpoint}`;
        }
        return `${this.config.api.baseUrl}${endpoint}`;
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
     * Get app information
     */
    getAppInfo() {
        return this.config?.app || {};
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
     * Log debug information if debug mode is enabled
     */
    debug(...args) {
        if (this.isDebug()) {
            console.log(`[${this.getEnvironment().toUpperCase()}]`, ...args);
        }
    }

    /**
     * Make authenticated API request with automatic token handling
     */
    async apiRequest(endpoint, options = {}) {
        if (!this.loaded) {
            await this.init();
        }

        const token = localStorage.getItem('access_token');
        const url = this.getApiUrl(endpoint);

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

            // Handle authentication errors
            if (response.status === 401) {
                localStorage.removeItem('access_token');
                localStorage.removeItem('user_email');
                if (window.location.pathname !== '/frontend/pages/auth/login.html') {
                    window.location.href = '/frontend/pages/auth/login.html';
                }
                return null;
            }

            return response;
        } catch (error) {
            this.debug('API request failed:', error);
            throw error;
        }
    }

    /**
     * Show notification based on environment
     */
    showNotification(message, type = 'info') {
        if (this.isDebug()) {
            console.log(`[${type.toUpperCase()}]`, message);
        }

        // You can implement a toast notification system here
        // For now, just alert in development
        if (this.getEnvironment() === 'development') {
            alert(`${type.toUpperCase()}: ${message}`);
        }
    }
}

// Create global instance (debug version)
console.log("=== STARTING INSTANCE CREATION ===");
console.log("1. AppConfig before instance creation:", typeof AppConfig);
console.log("2. AppConfig is:", AppConfig);

try {
    // Store the class first
    console.log("3. Storing class reference...");
    const AppConfigClass = AppConfig;
    console.log("4. AppConfigClass:", typeof AppConfigClass);

    // Create instance from the stored class
    console.log("5. Creating new instance...");
    const newInstance = new AppConfigClass();
    console.log("6. New instance created:", typeof newInstance);
    console.log("7. New instance.init exists:", typeof newInstance.init);
    console.log("8. New instance methods:", Object.getOwnPropertyNames(newInstance));

    // Assign to window
    console.log("9. Assigning to window.AppConfig...");
    window.AppConfig = newInstance;
    console.log("10. window.AppConfig after assignment:", typeof window.AppConfig);
    console.log("11. window.AppConfig.init:", typeof window.AppConfig.init);

    // Verify it worked
    if (typeof window.AppConfig.init === 'function') {
        console.log('✅ AppConfig instance created successfully');
    } else {
        console.log('❌ Instance creation failed - init method missing');
        console.log('window.AppConfig is:', window.AppConfig);
    }
} catch (error) {
    console.error('❌ Exception during instance creation:', error);
}

console.log("=== FINAL STATE ===");
console.log("Final AppConfig:", typeof AppConfig);
console.log("Final window.AppConfig:", typeof window.AppConfig);
console.log("=== END DEBUG ===");