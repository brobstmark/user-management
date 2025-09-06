/**
 * 🔒 Registration Page Enhancements
 * Adds specific functionality for the registration form
 * Works with the enterprise Auth class
 */

class RegisterPage {
    constructor() {
        this.initialized = false;
    }

    /**
     * Initialize registration page functionality
     */
    async init() {
        if (this.initialized) return;

        // Ensure dependencies are ready
        if (!window.Auth?.initialized) {
            await window.Auth?.init();
        }

        this.setupPasswordToggles();
        this.setupTermsValidation();
        this.setupFormEnhancements();

        this.initialized = true;
        console.log('✅ Registration page initialized');
    }

    /**
     * 👁️ Setup password visibility toggles
     */
    setupPasswordToggles() {
        // Password toggle
        const passwordToggle = document.getElementById('passwordToggle');
        const passwordInput = document.getElementById('password');

        if (passwordToggle && passwordInput) {
            passwordToggle.addEventListener('click', () => {
                this.togglePasswordVisibility(passwordInput, passwordToggle);
            });
        }

        // Confirm password toggle
        const confirmPasswordToggle = document.getElementById('confirmPasswordToggle');
        const confirmPasswordInput = document.getElementById('confirmPassword');

        if (confirmPasswordToggle && confirmPasswordInput) {
            confirmPasswordToggle.addEventListener('click', () => {
                this.togglePasswordVisibility(confirmPasswordInput, confirmPasswordToggle);
            });
        }
    }

    /**
     * Toggle password visibility
     */
    togglePasswordVisibility(input, toggle) {
        if (input.type === 'password') {
            input.type = 'text';
            toggle.textContent = '🙈';
            toggle.setAttribute('aria-label', 'Hide password');
        } else {
            input.type = 'password';
            toggle.textContent = '👁️';
            toggle.setAttribute('aria-label', 'Show password');
        }
    }

    /**
     * 📋 Setup terms checkbox validation
     */
    setupTermsValidation() {
        const termsCheckbox = document.getElementById('termsAgreement');
        const registerForm = document.getElementById('registerForm');

        if (!termsCheckbox || !registerForm) return;

        // Validate terms on form submission
        registerForm.addEventListener('submit', (e) => {
            if (!termsCheckbox.checked) {
                e.preventDefault();
                this.showFieldError(termsCheckbox, 'You must agree to the Terms of Service to register');
                termsCheckbox.focus();
                return false;
            } else {
                this.hideFieldError(termsCheckbox);
            }
        });

        // Clear error when checked
        termsCheckbox.addEventListener('change', () => {
            if (termsCheckbox.checked) {
                this.hideFieldError(termsCheckbox);
            }
        });
    }

    /**
     * 🔧 Setup additional form enhancements
     */
    setupFormEnhancements() {
        // Enhanced name field validation
        this.setupNameValidation();

        // Enhanced username validation
        this.setupUsernameValidation();

        // Form submission enhancement
        this.setupFormSubmissionFeedback();
    }

    /**
     * Setup name field validation
     */
    setupNameValidation() {
        const firstNameInput = document.getElementById('firstName');
        const lastNameInput = document.getElementById('lastName');

        if (firstNameInput) {
            firstNameInput.addEventListener('blur', () => {
                this.validateNameField(firstNameInput, 'First name');
            });
        }

        if (lastNameInput) {
            lastNameInput.addEventListener('blur', () => {
                this.validateNameField(lastNameInput, 'Last name');
            });
        }
    }

    /**
     * Validate name field
     */
    validateNameField(input, fieldName) {
        const value = input.value.trim();

        if (value && !/^[a-zA-Z\s\-']+$/.test(value)) {
            input.classList.add('error');
            this.showFieldError(input, `${fieldName} can only contain letters, spaces, hyphens, and apostrophes`);
            return false;
        } else if (value && value.length > 100) {
            input.classList.add('error');
            this.showFieldError(input, `${fieldName} must be 100 characters or less`);
            return false;
        } else {
            input.classList.remove('error');
            input.classList.add('success');
            this.hideFieldError(input);
            return true;
        }
    }

    /**
     * Setup username validation
     */
    setupUsernameValidation() {
        const usernameInput = document.getElementById('username');

        if (usernameInput) {
            usernameInput.addEventListener('blur', () => {
                this.validateUsername(usernameInput);
            });
        }
    }

    /**
     * Validate username
     */
    validateUsername(input) {
        const value = input.value.trim();

        // Username is optional, so empty is OK
        if (!value) {
            input.classList.remove('error', 'success');
            this.hideFieldError(input);
            return true;
        }

        if (value.length < 3) {
            input.classList.add('error');
            this.showFieldError(input, 'Username must be at least 3 characters long');
            return false;
        } else if (!/^[a-zA-Z0-9_-]+$/.test(value)) {
            input.classList.add('error');
            this.showFieldError(input, 'Username can only contain letters, numbers, underscores, and hyphens');
            return false;
        } else {
            input.classList.remove('error');
            input.classList.add('success');
            this.hideFieldError(input);
            return true;
        }
    }

    /**
     * Setup form submission feedback
     */
    setupFormSubmissionFeedback() {
        const registerForm = document.getElementById('registerForm');

        if (!registerForm) return;

        registerForm.addEventListener('submit', (e) => {
            // Additional client-side validation before Auth handles it
            if (!this.validateAllFields()) {
                e.preventDefault();
                return false;
            }
        });
    }

    /**
     * Validate all form fields
     */
    validateAllFields() {
        let isValid = true;

        // Validate email (Auth class handles this, but double-check)
        const emailInput = document.getElementById('email');
        if (emailInput && !emailInput.value.trim()) {
            this.showFieldError(emailInput, 'Email address is required');
            isValid = false;
        }

        // Validate password (Auth class handles this, but double-check)
        const passwordInput = document.getElementById('password');
        if (passwordInput && !passwordInput.value) {
            this.showFieldError(passwordInput, 'Password is required');
            isValid = false;
        }

        // Validate confirm password
        const confirmPasswordInput = document.getElementById('confirmPassword');
        if (confirmPasswordInput && passwordInput) {
            if (confirmPasswordInput.value !== passwordInput.value) {
                this.showFieldError(confirmPasswordInput, 'Passwords do not match');
                isValid = false;
            }
        }

        // Validate terms agreement
        const termsCheckbox = document.getElementById('termsAgreement');
        if (termsCheckbox && !termsCheckbox.checked) {
            this.showFieldError(termsCheckbox, 'You must agree to the Terms of Service');
            isValid = false;
        }

        return isValid;
    }

    /**
     * Show field-specific error
     */
    showFieldError(input, message) {
        this.hideFieldError(input);

        const error = document.createElement('span');
        error.className = 'field-error';
        error.textContent = String(message).substring(0, 100);

        // For checkbox, append to parent container
        if (input.type === 'checkbox') {
            const container = input.closest('.checkbox-group');
            if (container) {
                container.appendChild(error);
            }
        } else {
            input.parentNode.appendChild(error);
        }

        input.classList.add('error');
    }

    /**
     * Hide field-specific error
     */
    hideFieldError(input) {
        // Remove from immediate parent
        const error = input.parentNode?.querySelector('.field-error');
        if (error) {
            error.remove();
        }

        // For checkboxes, also check parent container
        if (input.type === 'checkbox') {
            const container = input.closest('.checkbox-group');
            const containerError = container?.querySelector('.field-error');
            if (containerError) {
                containerError.remove();
            }
        }

        input.classList.remove('error');
    }

    /**
     * Cleanup
     */
    destroy() {
        this.initialized = false;
    }
}

// 🔒 Create and expose global instance
(function() {
    'use strict';

    const registerPageInstance = new RegisterPage();

    try {
        Object.defineProperty(window, 'RegisterPage', {
            value: registerPageInstance,
            writable: false,
            configurable: false
        });
    } catch (error) {
        window.RegisterPage = registerPageInstance;
    }
})();

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.RegisterPage?.init();
});