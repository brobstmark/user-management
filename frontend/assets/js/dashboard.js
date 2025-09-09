/**
 * Conversion-Focused Dashboard
 * Designed to get immediate customer sign-ups
 */

class ConversionDashboard {
    constructor() {
        this.userInfo = null;
        this.platforms = [];
        this.initialized = false;
        this.isCreatingPlatform = false;
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
        console.log('✅ Conversion Dashboard initialized');
    }

    /**
     * Load dashboard data and determine state
     */
    async loadDashboard() {
        try {
            // Load user info (this also checks authentication)
            this.userInfo = await window.Auth.getUserInfo();

            if (!this.userInfo) {
                console.warn('🔒 Not authenticated, redirecting to login');
                this._secureRedirect('../auth/login.html');
                return;
            }

            this._updateUserInterface();

            // Load existing platforms
            await this.loadPlatforms();

            // Show appropriate state
            this._showDashboard();

        } catch (error) {
            console.error('🚨 Dashboard load failed:', error);
            this._showError('Failed to load dashboard. Please refresh the page.');
        }
    }

    /**
     * Load user's existing platforms
     */
    async loadPlatforms() {
        try {
            const response = await window.Auth._apiRequest('/auth/platforms', {
                method: 'GET'
            });

            if (response?.ok) {
                this.platforms = await response.json();
            } else {
                this.platforms = [];
            }
        } catch (error) {
            console.warn('Could not load platforms:', error);
            this.platforms = [];
        }
    }

    /**
     * Update user interface elements
     */
    _updateUserInterface() {
        const userEmailEl = document.getElementById('userEmail');
        if (userEmailEl && this.userInfo) {
            const displayName = this._getDisplayName(this.userInfo);
            userEmailEl.textContent = displayName;
        }
    }

    /**
     * Show dashboard content based on user state
     */
    _showDashboard() {
        const loadingSection = document.getElementById('loadingSection');
        const dashboardContent = document.getElementById('dashboardContent');

        if (loadingSection) loadingSection.style.display = 'none';
        if (dashboardContent) dashboardContent.style.display = 'block';

        // Determine which state to show
        if (this.platforms.length === 0) {
            this._showNewUserState();
        } else {
            this._showExistingPlatformsState();
        }
    }

    /**
     * Show new user state (conversion-focused)
     */
    _showNewUserState() {
        const newUserState = document.getElementById('newUserState');
        const successState = document.getElementById('successState');
        const platformsList = document.getElementById('platformsList');

        if (newUserState) newUserState.style.display = 'block';
        if (successState) successState.style.display = 'none';
        if (platformsList) platformsList.style.display = 'none';
    }

    /**
     * Show success state after platform creation
     */
    _showSuccessState(platformData) {
        const newUserState = document.getElementById('newUserState');
        const successState = document.getElementById('successState');
        const platformsList = document.getElementById('platformsList');

        if (newUserState) newUserState.style.display = 'none';
        if (successState) successState.style.display = 'block';
        if (platformsList) platformsList.style.display = 'none';

        // Update success state with platform data
        this._populateSuccessState(platformData);

        // Update progress indicators
        this._updateProgressSteps(3);
    }

    /**
     * Show existing platforms state
     */
    _showExistingPlatformsState() {
        const newUserState = document.getElementById('newUserState');
        const successState = document.getElementById('successState');
        const platformsList = document.getElementById('platformsList');

        if (newUserState) newUserState.style.display = 'none';
        if (successState) successState.style.display = 'none';
        if (platformsList) platformsList.style.display = 'block';

        this._populatePlatformsList();
    }

    /**
     * Setup event listeners
     */
    setupEventListeners() {
        // Platform creation form
        const platformForm = document.getElementById('platformForm');
        if (platformForm) {
            platformForm.addEventListener('submit', this.handleCreatePlatform.bind(this));
        }

        // Copy code button
        const copyCodeBtn = document.getElementById('copyCodeBtn');
        if (copyCodeBtn) {
            copyCodeBtn.addEventListener('click', this.handleCopyCode.bind(this));
        }

        // Action buttons
        const createAnotherBtn = document.getElementById('createAnotherBtn');
        if (createAnotherBtn) {
            createAnotherBtn.addEventListener('click', this.handleCreateAnother.bind(this));
        }

        const viewDocsBtn = document.getElementById('viewDocsBtn');
        if (viewDocsBtn) {
            viewDocsBtn.addEventListener('click', this.handleViewDocs.bind(this));
        }

        const addPlatformBtn = document.getElementById('addPlatformBtn');
        if (addPlatformBtn) {
            addPlatformBtn.addEventListener('click', this.handleAddPlatform.bind(this));
        }

        // Logout
        const logoutBtn = document.getElementById('logoutBtn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', this.handleLogout.bind(this));
        }

        // Auto-fill domain based on platform name
        const platformName = document.getElementById('platformName');
        const platformDomain = document.getElementById('platformDomain');


        if (platformName && platformDomain) {
            platformName.addEventListener('input', (e) => {
                if (!platformDomain.value) {
                    const suggestion = this._suggestDomain(e.target.value);
                    platformDomain.placeholder = suggestion;
                }
            });
        }
    }

    /**
     * Handle platform creation
     */
    async handleCreatePlatform(e) {
        e.preventDefault();

        if (this.isCreatingPlatform) return;

        const formData = new FormData(e.target);
        const platformName = formData.get('platformName') || document.getElementById('platformName').value;
        const platformDomain = formData.get('platformDomain') || document.getElementById('platformDomain').value;
        const description = formData.get('description') || document.getElementById('description').value;
        const returnUrl = formData.get('returnUrl') || document.getElementById('returnUrl').value;

        if (!platformName || !platformDomain || !description || !returnUrl) {
            this._showError('Please fill in all required fields');
            return;
        }

        this.isCreatingPlatform = true;
        this._setButtonLoading(true);
        this._updateProgressSteps(2);

        try {
            // Create platform via API
            const platformData = await this._createPlatformAPI(
                platformName.trim(),
                platformDomain.trim(),
                description.trim(),
                returnUrl.trim()
            );
            if (platformData) {
                // Add to platforms list
                this.platforms.push(platformData);

                // Show success state
                this._showSuccessState(platformData);

                this._showMessage('success', '🎉 Platform Created Successfully!', 'Your integration code is ready to use.');
            } else {
                throw new Error('Platform creation failed');
            }

        } catch (error) {
            const errorParts = error.message.split('|');
            const errorType = errorParts.length > 1 ? errorParts[0] : 'validation';
            const errorMessage = errorParts.length > 1 ? errorParts[1] : error.message;

            this._showError(errorMessage || 'Unable to create platform', errorType);
            this._updateProgressSteps(1);
        } finally {
            this.isCreatingPlatform = false;
            this._setButtonLoading(false);
        }
    }

    /**
     * Create platform via API
     */
    async _createPlatformAPI(name, domain, description, returnUrl) {
        try {
            const response = await window.Auth._apiRequest('/auth/create-platform', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    name: name,
                    domain: domain,
                    description: description,
                    return_url: returnUrl
                })
            });

            if (response?.ok) {
                const data = await response.json();
                return {
                    id: data.platform.id,
                    name: data.platform.name,
                    slug: data.platform.slug,
                    domain: data.platform.domain,
                    api_key: data.api_key,
                    api_key_prefix: data.platform.api_key_prefix,
                    created_at: data.platform.created_at,
                    is_active: data.platform.is_active
                };
            } else {
                const errorData = await response.json();
                this._handleApiError(response.status, errorData);
            }

        } catch (error) {
            if (error.name === 'TypeError' || error.message.includes('fetch')) {
                throw new Error('network|Unable to connect to server. Please check your internet connection.');
            }
            throw error;
        }
    }

    /**
     * Handle API error responses with specific user-friendly messages
     */
    _handleApiError(status, errorData) {
        const firstError = errorData.detail?.errors?.[0] || errorData.detail?.message || '';

        // Domain-specific errors
        if (firstError.includes('domain') && (firstError.includes('already') || firstError.includes('exists'))) {
            throw new Error('validation|This domain is already in use. Please choose a different domain.');
        }

        // Name conflicts
        if (firstError.includes('name') && (firstError.includes('already') || firstError.includes('exists'))) {
            throw new Error('validation|This platform name is taken. Please choose a different name.');
        }

        // Invalid domain format
        if (firstError.includes('invalid domain') || firstError.includes('domain format')) {
            throw new Error('validation|Please enter a valid domain (example: myapp.com)');
        }

        // Invalid URL format
        if (firstError.includes('return_url') || firstError.includes('Invalid URL') || firstError.includes('url')) {
            throw new Error('validation|Please enter a valid URL starting with https://');
        }

        // Rate limiting
        if (status === 429) {
            throw new Error('network|Too many requests. Please wait a moment and try again.');
        }

        // Server errors
        if (status >= 500) {
            throw new Error('network|Server temporarily unavailable. Please try again in a few minutes.');
        }

        // Authentication errors
        if (status === 401) {
            throw new Error('network|Session expired. Please refresh the page and try again.');
        }

        // Default fallback
        throw new Error('validation|Unable to create platform. Please check your information and try again.');
    }

    /**
     * Clear existing error styling
     */
    _clearErrors() {
        // Remove form field error styling
        document.querySelectorAll('.form-group.error').forEach(group => {
            group.classList.remove('error');
        });

        // Clear message container
        const messageContainer = document.getElementById('messageContainer');
        if (messageContainer) {
            messageContainer.innerHTML = '';
        }
    }

    /**
     * Populate success state with platform data
     */
    _populateSuccessState(platformData) {
        // Update platform details
        const platformIdEl = document.getElementById('createdPlatformId');
        const apiKeyEl = document.getElementById('createdApiKey');
        const domainEl = document.getElementById('createdDomain');

        if (platformIdEl) platformIdEl.textContent = platformData.id;
        if (apiKeyEl) apiKeyEl.textContent = platformData.api_key;
        if (domainEl) domainEl.textContent = platformData.domain;

        // Generate and display integration code
        const integrationCode = this._generateIntegrationCode(platformData);
        const codeEl = document.getElementById('integrationCode');
        if (codeEl) {
            codeEl.textContent = integrationCode;
        }
    }

    /**
     * Generate integration code for the platform
     */
    _generateIntegrationCode(platformData) {
        const baseUrl = window.AppConfig?.api?.baseUrl || '/api/v1';

        return `<!-- Add this to your website's HTML -->
<script>
async function checkAuth() {
    try {
        const response = await fetch('${baseUrl}/auth/validate?platform_id=${platformData.id}', {
            credentials: 'include'
        });
        const data = await response.json();

        if (data.valid) {
            // User is logged in - show your content
            showYourContent(data.user);
        } else {
            // Redirect to login
            const returnUrl = encodeURIComponent(window.location.href);
            window.location.href = '/frontend/pages/auth/login.html?return_url=' + returnUrl + '&platform_id=${platformData.id}';
        }
    } catch (error) {
        // Redirect to login on error
        window.location.href = '/frontend/pages/auth/login.html?platform_id=${platformData.id}';
    }
}

function showYourContent(user) {
    // Replace this with your app's content
    document.body.innerHTML = '<h1>Welcome, ' + user.email + '!</h1><p>You are now logged in.</p>';
}

// Check authentication when page loads
window.onload = checkAuth;
</script>`;
    }

    /**
     * Handle copy code button
     */
    handleCopyCode(e) {
        e.preventDefault();

        const codeEl = document.getElementById('integrationCode');
        if (!codeEl) return;

        const code = codeEl.textContent;

        // Copy to clipboard
        navigator.clipboard.writeText(code).then(() => {
            // Update button temporarily
            const btn = e.target;
            const originalText = btn.textContent;
            btn.textContent = 'Copied!';
            btn.style.background = '#48bb78';

            setTimeout(() => {
                btn.textContent = originalText;
                btn.style.background = '';
            }, 2000);

            this._showMessage('success', '📋 Code Copied!', 'Integration code copied to clipboard.');
        }).catch(err => {
            console.error('Copy failed:', err);
            this._showError('Failed to copy code. Please select and copy manually.');
        });
    }

    /**
     * Handle create another platform
     */
    handleCreateAnother(e) {
        e.preventDefault();

        // Reset form
        const form = document.getElementById('platformForm');
        if (form) form.reset();

        // Show new user state again
        this._showNewUserState();
        this._updateProgressSteps(1);
    }

    /**
     * Handle view documentation
     */
    handleViewDocs(e) {
        e.preventDefault();
        // TODO: Open documentation in new tab
        this._showMessage('info', '📖 Coming Soon', 'Comprehensive documentation will be available soon.');
    }

    /**
     * Handle add platform (for existing users)
     */
    handleAddPlatform(e) {
        e.preventDefault();
        this._showNewUserState();
    }

    /**
     * Handle logout
     */
    async handleLogout(e) {
        e.preventDefault();
        try {
            await window.Auth.logout();
        } catch (error) {
            console.error('Logout failed:', error);
            this._secureRedirect('../auth/login.html');
        }
    }

    /**
     * Update progress steps
     */
    _updateProgressSteps(activeStep) {
        const steps = document.querySelectorAll('.step');
        steps.forEach((step, index) => {
            if (index + 1 <= activeStep) {
                step.classList.add('active');
            } else {
                step.classList.remove('active');
            }
        });
    }

    /**
     * Set button loading state
     */
    _setButtonLoading(loading) {
        const btn = document.getElementById('createBtn');
        const btnText = btn?.querySelector('.btn-text');
        const btnLoading = btn?.querySelector('.btn-loading');

        if (!btn) return;

        if (loading) {
            btn.disabled = true;
            if (btnText) btnText.style.display = 'none';
            if (btnLoading) btnLoading.style.display = 'block';
        } else {
            btn.disabled = false;
            if (btnText) btnText.style.display = 'block';
            if (btnLoading) btnLoading.style.display = 'none';
        }
    }



    /**
     * Suggest domain based on platform name
     */
    _suggestDomain(name) {
        if (!name) return 'myapp.com';

        const clean = name.toLowerCase()
            .replace(/[^a-zA-Z0-9]+/g, '')
            .substring(0, 20);

        return clean ? `${clean}.com` : 'myapp.com';
    }

    /**
     * Populate platforms list (for existing users)
     */
    _populatePlatformsList() {
        const grid = document.getElementById('platformsGrid');
        if (!grid) return;

        if (this.platforms.length === 0) {
            grid.innerHTML = '<p>No platforms created yet.</p>';
            return;
        }

        grid.innerHTML = this.platforms.map(platform => `
            <div class="platform-card">
                <h3>${this._sanitizeText(platform.name)}</h3>
                <p>${this._sanitizeText(platform.domain)}</p>
                <div class="platform-actions">
                    <button class="btn-secondary">Manage</button>
                    <button class="btn-primary">View Code</button>
                </div>
            </div>
        `).join('');
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
     * Show message to user
     */
    _showMessage(type, title, description = '') {
        const messageContainer = document.getElementById('messageContainer');
        if (!messageContainer) {
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

        // Scroll to top to show message
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    /**
     * Show error message
     */
    _showError(message, type = 'validation') {
        // Clear any existing errors first
        this._clearErrors();

        // Different styling based on error type
        const errorClass = type === 'network' ? 'error-network' : 'error-validation';

        this._showMessage('error', 'Unable to Create Platform', message);

        // For validation errors, also highlight the relevant form fields
        if (type === 'validation') {
            this._highlightErrorFields(message);
        }
    }

    /**
    * Highlight error fields
    */
    _highlightErrorFields(errorMessage) {
        // Remove existing error styling
        document.querySelectorAll('.form-group.error').forEach(group => {
            group.classList.remove('error');
        });

        // Add error styling based on message content
        if (errorMessage.toLowerCase().includes('domain')) {
            const domainGroup = document.getElementById('platformDomain')?.closest('.form-group');
            domainGroup?.classList.add('error');
        }

        if (errorMessage.toLowerCase().includes('name')) {
            const nameGroup = document.getElementById('platformName')?.closest('.form-group');
            nameGroup?.classList.add('error');
        }

        if (errorMessage.toLowerCase().includes('url')) {
            const urlGroup = document.getElementById('returnUrl')?.closest('.form-group');
            urlGroup?.classList.add('error');
        }
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
            console.error('🚨 Blocked dangerous redirect:', path);
            return;
        }
        window.location.href = path;
    }

    /**
     * Sanitize text for display
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
        this.initialized = false;
    }
}

// Create and expose global instance
(function() {
    'use strict';

    const dashboardInstance = new ConversionDashboard();

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