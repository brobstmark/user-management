// File: frontend/assets/js/logger.js
// 🛡️ Secure Frontend Logger Client - Integrates with Backend Logging System

class SecureFrontendLogger {
    constructor(config = {}) {
        this.config = {
            apiEndpoint: '/api/v1/logs/frontend',
            maxBatchSize: 25,  // Reduced to match backend limit
            batchInterval: 5000, // 5 seconds
            maxLogLevel: 'INFO', // DEBUG, INFO, WARN, ERROR
            enabledInProduction: false,
            enableConsoleLogging: true,
            rateLimitPerMinute: 50, // Reduced for safety
            maxMessageLength: 500,
            retryAttempts: 3,
            retryDelay: 1000,
            ...config
        };

        this.logQueue = [];
        this.lastFlush = Date.now();
        this.requestCount = 0;
        this.lastReset = Date.now();
        this.isOnline = navigator.onLine;

        // Start batch processing
        this.startBatchTimer();
        this.setupNetworkHandlers();

        // Bind methods
        this.debug = this.debug.bind(this);
        this.info = this.info.bind(this);
        this.warn = this.warn.bind(this);
        this.error = this.error.bind(this);
        this.logAuthEvent = this.logAuthEvent.bind(this);
        this.logSecurityEvent = this.logSecurityEvent.bind(this);
    }

    // 🔒 Network status monitoring
    setupNetworkHandlers() {
        window.addEventListener('online', () => {
            this.isOnline = true;
            if (this.config.enableConsoleLogging) {
                console.info('[Logger] Network restored, resuming log transmission');
            }
            this.flushPendingLogs();
        });

        window.addEventListener('offline', () => {
            this.isOnline = false;
            if (this.config.enableConsoleLogging) {
                console.warn('[Logger] Network offline, queuing logs locally');
            }
        });
    }

    // 🔒 Sanitize sensitive data using patterns from backend PII filter
    sanitizeData(data) {
        if (typeof data === 'string') {
            return data
                // Email pattern
                .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '[EMAIL_REDACTED]')
                // Token patterns
                .replace(/\b[A-Za-z0-9+/]{20,}={0,2}\b/g, '[TOKEN_REDACTED]')
                .replace(/\b[A-Fa-f0-9]{32,}\b/g, '[TOKEN_REDACTED]')
                .replace(/\bBearereyJ[A-Za-z0-9+/=]+\b/g, '[TOKEN_REDACTED]')
                .replace(/\btoken[=:]\s*[A-Za-z0-9+/=]+/gi, 'token=[TOKEN_REDACTED]')
                .replace(/\bsk_[a-z]+_[A-Za-z0-9]+/gi, '[API_KEY_REDACTED]')
                // Password patterns
                .replace(/\bpassword[=:]\s*\S+/gi, 'password=[PASSWORD_REDACTED]')
                .replace(/\bpwd[=:]\s*\S+/gi, 'pwd=[PASSWORD_REDACTED]')
                .replace(/\bpass[=:]\s*\S+/gi, 'pass=[PASSWORD_REDACTED]')
                // Credit card pattern
                .replace(/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, '[CREDIT_CARD_REDACTED]')
                // SSN pattern
                .replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[SSN_REDACTED]')
                // Phone patterns
                .replace(/\b\d{3}-\d{3}-\d{4}\b/g, '[PHONE_REDACTED]')
                .replace(/\b\(\d{3}\)\s?\d{3}-\d{4}\b/g, '[PHONE_REDACTED]')
                .substring(0, this.config.maxMessageLength);
        }

        if (typeof data === 'object' && data !== null) {
            const sanitized = {};
            for (const [key, value] of Object.entries(data)) {
                const lowerKey = key.toLowerCase();
                const sensitiveKeys = [
                    'password', 'pwd', 'pass', 'token', 'key', 'secret',
                    'email', 'username', 'user_email', 'credit_card',
                    'ssn', 'social_security', 'phone', 'authorization',
                    'cookie', 'session_token', 'credential'
                ];

                if (sensitiveKeys.some(sensitive => lowerKey.includes(sensitive))) {
                    sanitized[key] = '[REDACTED]';
                } else if (typeof value === 'string') {
                    sanitized[key] = this.sanitizeData(value);
                } else if (typeof value === 'object') {
                    sanitized[key] = this.sanitizeData(value);
                } else {
                    sanitized[key] = value;
                }
            }
            return sanitized;
        }

        return data;
    }

    // 🔒 Rate limiting check
    checkRateLimit() {
        const now = Date.now();
        if (now - this.lastReset > 60000) {
            this.requestCount = 0;
            this.lastReset = now;
        }

        return this.requestCount < this.config.rateLimitPerMinute;
    }

    // 🔒 Create secure log entry
    createLogEntry(level, message, context = {}) {
        if (!this.checkRateLimit()) {
            if (this.config.enableConsoleLogging) {
                console.warn('[Logger] Rate limit exceeded');
            }
            return null;
        }

        const sanitizedMessage = this.sanitizeData(message);
        const sanitizedContext = this.sanitizeData(context);

        const logEntry = {
            timestamp: new Date().toISOString(),
            level: level.toUpperCase(),
            message: sanitizedMessage,
            context: sanitizedContext,
            url: window.location.href,
            user_agent: navigator.userAgent.substring(0, 500),
            session_id: this.getSessionId(),
            source: 'frontend'
        };

        this.requestCount++;
        return logEntry;
    }

    // 🔒 Get or create session ID (non-sensitive)
    getSessionId() {
        let sessionId = sessionStorage.getItem('logSessionId');
        if (!sessionId) {
            sessionId = 'sess_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
            sessionStorage.setItem('logSessionId', sessionId);
        }
        return sessionId;
    }

    // 🔒 Check if logging is enabled
    isLoggingEnabled(level) {
        const levels = ['DEBUG', 'INFO', 'WARN', 'ERROR'];
        const currentLevel = levels.indexOf(this.config.maxLogLevel);
        const messageLevel = levels.indexOf(level.toUpperCase());

        if (messageLevel < currentLevel) {
            return false;
        }

        // Disable debug logging in production unless explicitly enabled
        if (level === 'DEBUG' &&
            window.location.hostname !== 'localhost' &&
            !this.config.enabledInProduction) {
            return false;
        }

        return true;
    }

    // 🔒 Log methods
    debug(message, context = {}) {
        this.log('DEBUG', message, context);
    }

    info(message, context = {}) {
        this.log('INFO', message, context);
    }

    warn(message, context = {}) {
        this.log('WARN', message, context);
    }

    error(message, context = {}) {
        this.log('ERROR', message, context);
    }

    // 🔒 Main logging method
    log(level, message, context = {}) {
        if (!this.isLoggingEnabled(level)) {
            return;
        }

        // Console logging (development)
        if (this.config.enableConsoleLogging) {
            const sanitizedMessage = this.sanitizeData(message);
            const sanitizedContext = this.sanitizeData(context);

            const prefix = '[FRONTEND]';
            switch (level.toUpperCase()) {
                case 'DEBUG':
                    console.debug(`${prefix} ${sanitizedMessage}`, sanitizedContext);
                    break;
                case 'INFO':
                    console.info(`${prefix} ${sanitizedMessage}`, sanitizedContext);
                    break;
                case 'WARN':
                    console.warn(`${prefix} ${sanitizedMessage}`, sanitizedContext);
                    break;
                case 'ERROR':
                    console.error(`${prefix} ${sanitizedMessage}`, sanitizedContext);
                    break;
            }
        }

        // Remote logging
        const logEntry = this.createLogEntry(level, message, context);
        if (logEntry) {
            this.logQueue.push(logEntry);

            // Immediate flush for errors
            if (level.toUpperCase() === 'ERROR') {
                this.flush();
            }
        }
    }

    // 🔒 Authentication event logging (integrates with backend auth logger)
    logAuthEvent(eventType, details = {}) {
        this.info(`Auth Event: ${eventType}`, {
            event_type: eventType,
            auth_event: true,
            ...details
        });
    }

    // 🔒 Security event logging (integrates with backend security logger)
    logSecurityEvent(eventType, details = {}) {
        this.warn(`Security Event: ${eventType}`, {
            event_type: eventType,
            security_event: true,
            ...details
        });
    }

    // 🔒 Batch timer
    startBatchTimer() {
        setInterval(() => {
            if (this.logQueue.length > 0 && this.isOnline) {
                this.flush();
            }
        }, this.config.batchInterval);
    }

    // 🔒 Send logs to backend with retry logic
    async flush() {
        if (this.logQueue.length === 0) {
            return;
        }

        if (!this.isOnline) {
            if (this.config.enableConsoleLogging) {
                console.warn('[Logger] Offline - logs queued for later transmission');
            }
            return;
        }

        const logsToSend = this.logQueue.splice(0, this.config.maxBatchSize);
        this.lastFlush = Date.now();

        const payload = {
            logs: logsToSend,
            client_info: {
                timestamp: new Date().toISOString(),
                user_agent: navigator.userAgent.substring(0, 500),
                url: window.location.href,
                viewport: `${window.innerWidth}x${window.innerHeight}`,
                language: navigator.language,
                platform: navigator.platform
            }
        };

        let lastError = null;

        for (let attempt = 1; attempt <= this.config.retryAttempts; attempt++) {
            try {
                const response = await fetch(this.config.apiEndpoint, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        // Include auth token if available
                        ...(this.getAuthToken() && {
                            'Authorization': `Bearer ${this.getAuthToken()}`
                        })
                    },
                    body: JSON.stringify(payload)
                });

                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }

                // Success - clear any pending logs for this batch
                this.clearPendingLogs(logsToSend);
                return;

            } catch (error) {
                lastError = error;

                if (attempt < this.config.retryAttempts) {
                    // Wait before retrying
                    await new Promise(resolve =>
                        setTimeout(resolve, this.config.retryDelay * attempt)
                    );
                } else {
                    // Final attempt failed
                    if (this.config.enableConsoleLogging) {
                        console.warn(`[Logger] Failed to send logs after ${this.config.retryAttempts} attempts:`, error.message);
                    }

                    // Store in localStorage for retry later
                    this.storePendingLogs(logsToSend);
                }
            }
        }
    }

    // 🔒 Get authentication token for API calls
    getAuthToken() {
        // Check various possible token storage locations
        const tokenKeys = ['access_token', 'authToken', 'token', 'jwt_token'];

        for (const key of tokenKeys) {
            const token = localStorage.getItem(key) || sessionStorage.getItem(key);
            if (token && token !== 'null' && token !== 'undefined') {
                return token;
            }
        }

        return null;
    }

    // 🔒 Store failed logs for retry
    storePendingLogs(logs) {
        try {
            const existingLogs = JSON.parse(localStorage.getItem('pendingLogs') || '[]');
            existingLogs.push(...logs);

            // Limit storage size (keep only last 100 logs)
            if (existingLogs.length > 100) {
                existingLogs.splice(0, existingLogs.length - 100);
            }

            localStorage.setItem('pendingLogs', JSON.stringify(existingLogs));
        } catch (error) {
            // localStorage might be full or unavailable
            if (this.config.enableConsoleLogging) {
                console.warn('[Logger] Failed to store pending logs:', error.message);
            }
        }
    }

    // 🔒 Clear successfully sent logs
    clearPendingLogs(sentLogs) {
        try {
            const pendingLogs = JSON.parse(localStorage.getItem('pendingLogs') || '[]');
            const remainingLogs = pendingLogs.filter(pending =>
                !sentLogs.some(sent =>
                    sent.timestamp === pending.timestamp && sent.message === pending.message
                )
            );

            if (remainingLogs.length > 0) {
                localStorage.setItem('pendingLogs', JSON.stringify(remainingLogs));
            } else {
                localStorage.removeItem('pendingLogs');
            }
        } catch (error) {
            // Ignore storage errors during cleanup
        }
    }

    // 🔒 Flush pending logs from localStorage
    async flushPendingLogs() {
        try {
            const pendingLogs = JSON.parse(localStorage.getItem('pendingLogs') || '[]');
            if (pendingLogs.length > 0) {
                this.logQueue.unshift(...pendingLogs);
                localStorage.removeItem('pendingLogs');
                await this.flush();
            }
        } catch (error) {
            if (this.config.enableConsoleLogging) {
                console.warn('[Logger] Error flushing pending logs:', error.message);
            }
        }
    }

    // 🔒 Manual flush
    async flushNow() {
        return await this.flush();
    }
}

// 🔒 Initialize global logger with environment detection
const isProduction = window.location.hostname !== 'localhost' &&
                    !window.location.hostname.includes('127.0.0.1') &&
                    !window.location.hostname.includes('dev') &&
                    !window.location.hostname.includes('staging');

window.FrontendLogger = new SecureFrontendLogger({
    enableConsoleLogging: !isProduction,
    enabledInProduction: false,
    maxLogLevel: isProduction ? 'WARN' : 'DEBUG'
});

// 🔒 Convenience functions that integrate with backend loggers
window.logDebug = window.FrontendLogger.debug;
window.logInfo = window.FrontendLogger.info;
window.logWarn = window.FrontendLogger.warn;
window.logError = window.FrontendLogger.error;
window.logAuthEvent = window.FrontendLogger.logAuthEvent;
window.logSecurityEvent = window.FrontendLogger.logSecurityEvent;

// 🔒 Global error handler - sends to backend error log
window.addEventListener('error', (event) => {
    window.FrontendLogger.error('JavaScript Error', {
        message: event.message,
        filename: event.filename,
        lineno: event.lineno,
        colno: event.colno,
        stack: event.error?.stack?.substring(0, 500),
        error_type: 'javascript_error'
    });
});

// 🔒 Unhandled promise rejection handler
window.addEventListener('unhandledrejection', (event) => {
    window.FrontendLogger.error('Unhandled Promise Rejection', {
        reason: event.reason?.toString()?.substring(0, 500),
        error_type: 'promise_rejection'
    });
});

// 🔒 Authentication state monitoring (integrates with backend auth logger)
document.addEventListener('DOMContentLoaded', () => {
    // Monitor localStorage/sessionStorage changes for auth tokens
    const originalSetItem = localStorage.setItem;
    localStorage.setItem = function(key, value) {
        if (key.toLowerCase().includes('token') || key.toLowerCase().includes('auth')) {
            window.FrontendLogger.logAuthEvent('Token Storage Change', {
                action: 'localStorage_set',
                key: key,
                storage_type: 'localStorage'
            });
        }
        return originalSetItem.apply(this, arguments);
    };

    const originalRemoveItem = localStorage.removeItem;
    localStorage.removeItem = function(key) {
        if (key.toLowerCase().includes('token') || key.toLowerCase().includes('auth')) {
            window.FrontendLogger.logAuthEvent('Token Storage Change', {
                action: 'localStorage_remove',
                key: key,
                storage_type: 'localStorage'
            });
        }
        return originalRemoveItem.apply(this, arguments);
    };

    // Monitor sessionStorage changes
    const originalSessionSetItem = sessionStorage.setItem;
    sessionStorage.setItem = function(key, value) {
        if (key.toLowerCase().includes('token') || key.toLowerCase().includes('auth')) {
            window.FrontendLogger.logAuthEvent('Token Storage Change', {
                action: 'sessionStorage_set',
                key: key,
                storage_type: 'sessionStorage'
            });
        }
        return originalSessionSetItem.apply(this, arguments);
    };

    const originalSessionRemoveItem = sessionStorage.removeItem;
    sessionStorage.removeItem = function(key) {
        if (key.toLowerCase().includes('token') || key.toLowerCase().includes('auth')) {
            window.FrontendLogger.logAuthEvent('Token Storage Change', {
                action: 'sessionStorage_remove',
                key: key,
                storage_type: 'sessionStorage'
            });
        }
        return originalSessionRemoveItem.apply(this, arguments);
    };
});

