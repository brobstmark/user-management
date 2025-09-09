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
            // Note: This endpoint doesn't exist yet - we'll need to create it
            // For now, assume empty array (new user state)
            this.platforms = [];

            // TODO: Implement when backend endpoint is ready
            // const response = await window.Auth._apiRequest('/auth/platforms', {
            //     method: 'GET'
            // });
            // if (response?.ok) {
            //     this.platforms = await response.json();
            // }
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

        if (!platformName || !platformDomain) {
            this._showError('Please fill in all required fields');
            return;
        }

        this.isCreatingPlatform = true;
        this._setButtonLoading(true);
        this._updateProgressSteps(2);

        try {
            // Create platform via API
            const platformData = await this._createPlatformAPI(platformName.trim(), platformDomain.trim());

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
            console.error('Platform creation failed:', error);
            this._showError('Failed to create platform. Please try again.');
            this._updateProgressSteps(1);
        } finally {
            this.isCreatingPlatform = false;
            this._setButtonLoading(false);
        }
    }

    /**
     * Create platform via API
     */
    async _createPlatformAPI(name, domain) {
        try {
            // Since we don't have the backend endpoint yet, simulate the API call
            // TODO: Replace with actual API call when endpoint is ready

            // Simulate API delay for better UX
            await new Promise(resolve => setTimeout(resolve, 1500));

            // Generate mock platform data (replace with real API response)
            const platformId = this._generatePlatformId(name);
            const apiKey = this._generateMockApiKey();

            const platformData = {
                id: platformId,
                name: name,
                domain: domain,
                api_key: apiKey,
                created_at: new Date().toISOString(),
                is_active: true
            };

            // TODO: Replace this mock with actual API call:
            /*
            const response = await window.Auth._apiRequest('/auth/create-platform', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    name: name,
                    domain: domain
                })
            });

            if (response?.ok) {
                return await response.json();
            } else {
                throw new Error('API request failed');
            }
            */

            return platformData;

        } catch (error) {
            console.error('API call failed:', error);
            throw error;
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
     * Generate platform ID from name
     */
    _generatePlatformId(name) {
        return name.toLowerCase()
            .replace(/[^a-zA-Z0-9]+/g, '-')
            .replace(/^-+|-+$/g, '')
            .substring(0, 50);
    }

    /**
     * Generate mock API key (replace with server-generated key)
     */
    _generateMockApiKey() {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let result = 'pk_';
        for (let i = 0; i < 32; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
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
    _showError(message) {
        this._showMessage('error', '❌ Error', message);
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