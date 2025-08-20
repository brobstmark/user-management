/**
 * 🔒 Enterprise Dashboard Management
 * Uses standardized Auth class and AppConfig
 * No sessionStorage - Pure httpOnly cookie authentication
 */

class Dashboard {
    constructor() {
        this.userInfo = null;
        this.verificationStatus = null;
        this.initialized = false;
    }

    /**
     * Initialize dashboard
     */
    async init() {
        if (this.initialized) return;

        // Ensure dependencies are ready
        if (!window.AppConfig?.loaded) {
            await window.AppConfig?.init();
        }

        if (!window.Auth?.initialized) {
            await window.Auth?.init();
        }

        this.setupEventListeners();
        await this.loadDashboard();

        this.initialized = true;
        console.log('✅ Dashboard initialized');
    }

    /**
     * 🔒 Load dashboard data
     */
    async loadDashboard() {
        try {
            // Check authentication status first
            const isAuthenticated = await window.Auth.checkAuthStatus();

            if (!isAuthenticated) {
                console.warn('🔐 Not authenticated, redirecting to login');
                this._secureRedirect('../auth/login.html');
                return;
            }

            // Load user profile data
            await this.loadUserProfile();

            // Load verification status
            await this.loadVerificationStatus();

            // Show dashboard content
            this._showDashboard();

        } catch (error) {
            console.error('🚨 Dashboard load failed:', error.name);
            this._showError('Failed to load dashboard. Please refresh the page.');
        }
    }

    /**
     * 🔒 Load user profile using Auth class
     */
    async loadUserProfile() {
        try {
            // Use Auth class to get user info (server-verified)
            this.userInfo = await window.Auth.getUserInfo();

            if (!this.userInfo) {
                throw new Error('Failed to get user information');
            }

            this._updateUserInterface();
            this._updateProfileGrid();

        } catch (error) {
            console.error('🚨 Failed to load user profile:', error.name);
            throw error;
        }
    }

    /**
     * 🔒 Load email verification status
     */
    async loadVerificationStatus() {
        try {
            const response = await window.Auth._apiRequest('/auth/verification-status', {
                method: 'GET'
            });

            if (response?.ok) {
                this.verificationStatus = await response.json();
                this._updateEmailStatus();
            } else {
                console.warn('⚠️ Could not load verification status');
            }
        } catch (error) {
            console.warn('⚠️ Failed to load verification status:', error.name);
        }
    }

    /**
     * Update user interface elements
     */
    _updateUserInterface() {
        const user = this.userInfo;

        // Update header
        const userEmailEl = document.getElementById('userEmail');
        if (userEmailEl) {
            userEmailEl.textContent = user.email || '—';
        }

        // Update welcome name
        const welcomeNameEl = document.getElementById('welcomeName');
        if (welcomeNameEl) {
            const displayName = this._getDisplayName(user);
            welcomeNameEl.textContent = displayName;
        }

        // Update avatar
        const userAvatarEl = document.getElementById('userAvatar');
        if (userAvatarEl) {
            const displayName = this._getDisplayName(user);
            userAvatarEl.textContent = (displayName[0] || 'U').toUpperCase();
        }

        // Update member since
        const memberSinceEl = document.getElementById('memberSince');
        if (memberSinceEl) {
            const created = user.created_at ? new Date(user.created_at) : null;
            memberSinceEl.textContent = created ? created.toLocaleDateString() : '—';
        }

        // Update profile status
        const profileStatusEl = document.getElementById('profileStatus');
        if (profileStatusEl) {
            profileStatusEl.textContent = user.is_active ? 'Active' : 'Inactive';
        }
    }

    /**
     * Update profile grid with user data
     */
    _updateProfileGrid() {
        const user = this.userInfo;
        const profileGrid = document.getElementById('profileGrid');

        if (!profileGrid) return;

        const fullName = this._getFullName(user);

        profileGrid.innerHTML = `
            <div class="profile-item">
                <span class="profile-label">Email:</span>
                <span class="profile-value">${this._sanitizeText(user.email || '—')}</span>
            </div>
            <div class="profile-item">
                <span class="profile-label">Full Name:</span>
                <span class="profile-value">${this._sanitizeText(fullName || 'Not set')}</span>
            </div>
            <div class="profile-item">
                <span class="profile-label">Username:</span>
                <span class="profile-value">${this._sanitizeText(user.username || 'Not set')}</span>
            </div>
            <div class="profile-item">
                <span class="profile-label">Phone:</span>
                <span class="profile-value">${this._sanitizeText(user.phone || 'Not set')}</span>
            </div>
            <div class="profile-item">
                <span class="profile-label">Account Status:</span>
                <span class="profile-value">
                    <span class="status-badge ${user.is_active ? 'status-verified' : 'status-pending'}">
                        ${user.is_active ? 'Active' : 'Inactive'}
                    </span>
                </span>
            </div>
            <div class="profile-item">
                <span class="profile-label">Last Login:</span>
                <span class="profile-value">${this._formatDate(user.last_login) || 'Never'}</span>
            </div>
        `;
    }

    /**
     * Update email verification status
     */
    _updateEmailStatus() {
        const emailStatusEl = document.getElementById('emailStatus');
        if (!emailStatusEl || !this.verificationStatus) return;

        if (this.verificationStatus.is_verified === true) {
            emailStatusEl.textContent = 'Verified ✅';
            emailStatusEl.style.color = '#28a745';
        } else if (this.verificationStatus.is_verified === false) {
            emailStatusEl.textContent = 'Pending ⏳';
            emailStatusEl.style.color = '#ffc107';
        } else {
            emailStatusEl.textContent = 'Unknown';
            emailStatusEl.style.color = '#6c757d';
        }
    }

    /**
     * Show dashboard content
     */
    _showDashboard() {
        const loadingSection = document.getElementById('loadingSection');
        const dashboardContent = document.getElementById('dashboardContent');

        if (loadingSection) loadingSection.style.display = 'none';
        if (dashboardContent) dashboardContent.style.display = 'block';
    }

    /**
     * Setup event listeners
     */
    setupEventListeners() {
        // Logout button
        const logoutBtn = document.getElementById('logoutBtn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', this.handleLogout.bind(this));
        }

        // Edit profile button
        const editProfileBtn = document.getElementById('editProfileBtn');
        if (editProfileBtn) {
            editProfileBtn.addEventListener('click', this.handleEditProfile.bind(this));
        }

        // Change password button
        const changePasswordBtn = document.getElementById('changePasswordBtn');
        if (changePasswordBtn) {
            changePasswordBtn.addEventListener('click', this.handleChangePassword.bind(this));
        }

        // Resend verification button
        const resendVerificationBtn = document.getElementById('resendVerificationBtn');
        if (resendVerificationBtn) {
            resendVerificationBtn.addEventListener('click', this.handleResendVerification.bind(this));
        }

        // Listen for auth state changes
        window.addEventListener('authStateChange', this.handleAuthStateChange.bind(this));
    }

    /**
     * 🔒 Handle logout
     */
    async handleLogout(e) {
        e.preventDefault();

        try {
            await window.Auth.logout();
        } catch (error) {
            console.error('🚨 Logout failed:', error.name);
            // Force redirect anyway
            this._secureRedirect('../auth/login.html');
        }
    }

    /**
     * Handle edit profile
     */
    handleEditProfile(e) {
        e.preventDefault();
        this._showMessage('info', '🚧 Coming Soon', 'Profile editing will be available in the next update.');
    }

    /**
     * Handle change password
     */
    handleChangePassword(e) {
        e.preventDefault();
        this._showMessage('info', '🚧 Coming Soon', 'Password change will be available in the next update.');
    }

    /**
     * 🔒 Handle resend verification
     */
    async handleResendVerification(e) {
        e.preventDefault();

        const button = e.target;
        const originalText = button.textContent;

        try {
            // Disable button and show loading
            button.disabled = true;
            button.textContent = 'Sending...';

            const response = await window.Auth._apiRequest('/auth/send-verification', {
                method: 'POST'
            });

            if (response?.ok) {
                this._showMessage('success', '✅ Verification Email Sent',
                    'Please check your inbox for the verification link.');

                // Reload verification status
                setTimeout(() => this.loadVerificationStatus(), 1000);
            } else {
                this._showMessage('error', '❌ Failed to Send Email',
                    'Please try again later.');
            }
        } catch (error) {
            console.error('🚨 Resend verification failed:', error.name);
            this._showMessage('error', '❌ Connection Error',
                'Unable to send email. Please try again.');
        } finally {
            // Re-enable button
            button.disabled = false;
            button.textContent = originalText;
        }
    }

    /**
     * Handle authentication state changes
     */
    handleAuthStateChange(event) {
        const { authenticated } = event.detail;

        if (!authenticated) {
            console.warn('🔐 Authentication lost, redirecting to login');
            this._secureRedirect('../auth/login.html');
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
     * 🔒 Show secure message
     */
    _showMessage(type, title, description = '') {
        const messageContainer = document.getElementById('messageContainer');

        if (!messageContainer) {
            // Fallback to alert if no container
            alert(`${title}: ${description}`);
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
        messageDiv.style.display = 'block';

        // Auto-hide success/info messages
        if (type === 'success' || type === 'info') {
            setTimeout(() => {
                if (messageDiv.parentNode) {
                    messageDiv.style.display = 'none';
                }
            }, 5000);
        }
    }

    /**
     * Show error message
     */
    _showError(message) {
        this._showMessage('error', '❌ Error', message);
    }

    /**
     * Get display name from user object
     */
    _getDisplayName(user) {
        if (user.first_name && user.last_name) {
            return `${user.first_name} ${user.last_name}`;
        } else if (user.first_name) {
            return user.first_name;
        } else if (user.username) {
            return user.username;
        } else if (user.email) {
            return user.email.split('@')[0];
        }
        return 'User';
    }

    /**
     * Get full name from user object
     */
    _getFullName(user) {
        if (user.first_name && user.last_name) {
            return `${user.first_name} ${user.last_name}`;
        } else if (user.first_name) {
            return user.first_name;
        }
        return null;
    }

    /**
     * Format date for display
     */
    _formatDate(dateString) {
        if (!dateString) return null;

        try {
            const date = new Date(dateString);
            return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
        } catch (error) {
            return null;
        }
    }

    /**
     * 🔒 Sanitize text for display (prevent XSS)
     */
    _sanitizeText(text) {
        const div = document.createElement('div');
        div.textContent = String(text || '');
        return div.innerHTML;
    }

    /**
     * Cleanup
     */
    destroy() {
        // Remove event listeners if needed
        this.initialized = false;
    }
}

// 🔒 Create and expose global instance
(function() {
    'use strict';

    const dashboardInstance = new Dashboard();

    try {
        Object.defineProperty(window, 'Dashboard', {
            value: dashboardInstance,
            writable: false,
            configurable: false
        });
    } catch (error) {
        window.Dashboard = dashboardInstance;
    }
})();

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.Dashboard?.init();
});