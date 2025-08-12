/**
 * User Management System - Main JavaScript
 */

// API Base URL
const API_BASE_URL = 'http://localhost:8000/api/v1';

// Main application object
const UserManagementApp = {
    init() {
        console.log('User Management System initialized');
        this.setupEventListeners();
    },

    setupEventListeners() {
        // Add global event listeners here
        document.addEventListener('DOMContentLoaded', () => {
            console.log('DOM loaded');
        });
    },

    // API helper methods will be added here
    api: {
        async request(endpoint, options = {}) {
            const url = `${API_BASE_URL}${endpoint}`;
            const config = {
                headers: {
                    'Content-Type': 'application/json',
                },
                ...options,
            };

            try {
                const response = await fetch(url, config);
                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.detail || 'Request failed');
                }

                return data;
            } catch (error) {
                console.error('API request failed:', error);
                throw error;
            }
        }
    }
};

// Initialize the application
UserManagementApp.init();
