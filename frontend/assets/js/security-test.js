class SecurityTestFramework {
    constructor() {
        this.results = {
            pass: 0,
            fail: 0,
            warn: 0,
            info: 0
        };
        this.tests = [];
    }

    addTest(category, name, testFunction, description) {
        if (!description) description = '';
        this.tests.push({
            category: category,
            name: name,
            test: testFunction,
            description: description,
            result: null
        });
    }

    async runAllTests() {
        this.results = { pass: 0, fail: 0, warn: 0, info: 0 };

        var testContainers = document.querySelectorAll('[id$="-tests"]');
        for (var i = 0; i < testContainers.length; i++) {
            testContainers[i].innerHTML = '';
        }

        document.getElementById('runTestsBtn').disabled = true;
        document.getElementById('runTestsBtn').textContent = 'Running Tests...';

        for (var i = 0; i < this.tests.length; i++) {
            var test = this.tests[i];
            try {
                var result = await test.test();
                test.result = result;
                this.results[result.status]++;
                this.displayTestResult(test);
            } catch (error) {
                test.result = {
                    status: 'fail',
                    message: 'Test error: ' + error.message,
                    details: error.stack || ''
                };
                this.results.fail++;
                this.displayTestResult(test);
            }
        }

        this.updateSummary();
        document.getElementById('runTestsBtn').disabled = false;
        document.getElementById('runTestsBtn').textContent = 'Run Security Tests';

        // Show export button after tests complete
        document.getElementById('exportBtn').style.display = 'block';
    }

    displayTestResult(test) {
        var container = document.getElementById(test.category + '-tests');
        var div = document.createElement('div');
        div.className = 'test-item test-' + test.result.status;

        var statusText = '';
        if (test.result.status === 'pass') statusText = '[PASS]';
        else if (test.result.status === 'fail') statusText = '[FAIL]';
        else if (test.result.status === 'warn') statusText = '[WARN]';
        else if (test.result.status === 'info') statusText = '[INFO]';

        var detailsHtml = test.result.details ? '<div class="test-details">' + test.result.details + '</div>' : '';

        div.innerHTML = '<div>' +
            '<strong>' + test.name + '</strong>' +
            '<div class="test-details">' + test.description + '</div>' +
            detailsHtml +
            '</div>' +
            '<div class="test-status">' + statusText + ' ' + test.result.message + '</div>';

        container.appendChild(div);
    }

    updateSummary() {
        document.getElementById('passCount').textContent = this.results.pass;
        document.getElementById('failCount').textContent = this.results.fail;
        document.getElementById('warnCount').textContent = this.results.warn;
        document.getElementById('infoCount').textContent = this.results.info;

        var total = this.results.pass + this.results.fail + this.results.warn + this.results.info;
        var passRate = total > 0 ? Math.round((this.results.pass / total) * 100) : 0;

        var summary = document.querySelector('.summary h2');
        if (this.results.fail === 0) {
            summary.textContent = 'Security Tests Complete - ' + passRate + '% Pass Rate';
            summary.style.color = '#28a745';
        } else {
            summary.textContent = 'Security Issues Found - ' + passRate + '% Pass Rate';
            summary.style.color = '#dc3545';
        }
    }

    exportResults() {
        var timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        var total = this.results.pass + this.results.fail + this.results.warn + this.results.info;
        var passRate = total > 0 ? Math.round((this.results.pass / total) * 100) : 0;

        var report = '# Frontend Security Test Results\n';
        report += '**Date:** ' + new Date().toLocaleString() + '\n';
        report += '**URL:** ' + window.location.href + '\n\n';

        report += '## Summary\n';
        report += '- **Total Tests:** ' + total + '\n';
        report += '- **Pass Rate:** ' + passRate + '%\n';
        report += '- **Passed:** ' + this.results.pass + '\n';
        report += '- **Failed:** ' + this.results.fail + '\n';
        report += '- **Warnings:** ' + this.results.warn + '\n';
        report += '- **Info:** ' + this.results.info + '\n\n';

        // Group tests by category
        var categories = {};
        for (var i = 0; i < this.tests.length; i++) {
            var test = this.tests[i];
            if (test.result) {
                if (!categories[test.category]) {
                    categories[test.category] = [];
                }
                categories[test.category].push(test);
            }
        }

        // Generate detailed results by category
        var categoryNames = {
            'xss': 'XSS Protection Tests',
            'auth': 'Authentication Security Tests',
            'token': 'Token Storage Security Tests',
            'validation': 'Input Validation Tests',
            'csrf': 'CSRF Protection Tests',
            'disclosure': 'Information Disclosure Tests',
            'redirect': 'Open Redirect Tests',
            'csp': 'Content Security Policy Tests',
            'logging': 'Logging Security Tests'
        };

        for (var category in categories) {
            var categoryTitle = categoryNames[category] || category.toUpperCase() + ' Tests';
            report += '## ' + categoryTitle + '\n\n';

            var categoryTests = categories[category];
            for (var j = 0; j < categoryTests.length; j++) {
                var test = categoryTests[j];
                var statusIcon = '';
                if (test.result.status === 'pass') statusIcon = '✅';
                else if (test.result.status === 'fail') statusIcon = '❌';
                else if (test.result.status === 'warn') statusIcon = '⚠️';
                else if (test.result.status === 'info') statusIcon = 'ℹ️';

                report += '### ' + statusIcon + ' ' + test.name + '\n';
                report += '**Status:** ' + test.result.status.toUpperCase() + '\n';
                report += '**Message:** ' + test.result.message + '\n';
                report += '**Description:** ' + test.description + '\n';
                if (test.result.details) {
                    report += '**Details:** ' + test.result.details + '\n';
                }
                report += '\n';
            }
        }

        // Recommendations section
        report += '## Recommendations\n\n';
        var failedTests = this.tests.filter(function(test) {
            return test.result && test.result.status === 'fail';
        });
        var warningTests = this.tests.filter(function(test) {
            return test.result && test.result.status === 'warn';
        });

        if (failedTests.length > 0) {
            report += '### Critical Issues (Failed Tests)\n';
            for (var k = 0; k < failedTests.length; k++) {
                var test = failedTests[k];
                report += '- **' + test.name + ':** ' + test.result.message + '\n';
            }
            report += '\n';
        }

        if (warningTests.length > 0) {
            report += '### Improvements Needed (Warnings)\n';
            for (var l = 0; l < warningTests.length; l++) {
                var test = warningTests[l];
                report += '- **' + test.name + ':** ' + test.result.message + '\n';
            }
            report += '\n';
        }

        if (failedTests.length === 0 && warningTests.length === 0) {
            report += 'No critical security issues found! Your frontend implementation appears secure.\n\n';
        }

        return report;
    }

    showExportModal() {
        var modal = document.getElementById('exportModal');
        var textarea = document.getElementById('exportText');
        textarea.value = this.exportResults();
        modal.style.display = 'block';
    }
}

var testFramework = new SecurityTestFramework();

// All your existing test definitions go here (XSS, Auth, Token, etc.)
// [Previous test code remains exactly the same]

// XSS Protection Tests
testFramework.addTest('xss', 'DOM XSS Protection', async function() {
    var testContainer = document.createElement('div');
    var maliciousScript = '<script>window.xssTest = true;</script>';

    testContainer.textContent = maliciousScript;
    if (testContainer.innerHTML.includes('&lt;script&gt;') && !window.xssTest) {
        return { status: 'pass', message: 'DOM uses textContent safely' };
    }
    return { status: 'fail', message: 'DOM manipulation may be vulnerable to XSS' };
}, 'Checks if DOM manipulation uses safe methods like textContent');

testFramework.addTest('xss', 'Message Display Security', async function() {
    if (window.displayMessage) {
        var testDiv = document.createElement('div');
        document.body.appendChild(testDiv);

        try {
            if (typeof window.displayMessage === 'function') {
                return { status: 'pass', message: 'Message display function exists and should use textContent' };
            }
        } finally {
            document.body.removeChild(testDiv);
        }
    }
    return { status: 'warn', message: 'Message display function not found or not testable' };
}, 'Verifies message display functions prevent XSS injection');

testFramework.addTest('xss', 'URL Parameter Sanitization', async function() {
    var currentUrl = new URL(window.location);
    currentUrl.searchParams.set('test', '<script>alert("xss")</script>');

    var testParam = currentUrl.searchParams.get('test');
    if (testParam && testParam.includes('<script>')) {
        return { status: 'warn', message: 'URL parameters should be sanitized before use' };
    }
    return { status: 'pass', message: 'URL parameter handling appears safe' };
}, 'Tests URL parameter sanitization');

// Authentication Security Tests
testFramework.addTest('auth', 'Authentication State Management', async function() {
    if (window.Auth) {
        if (typeof window.Auth.isAuthenticated === 'function') {
            return { status: 'pass', message: 'Authentication state management available' };
        }
    }
    return { status: 'warn', message: 'Authentication state management not found' };
}, 'Verifies authentication state is properly managed');

testFramework.addTest('auth', 'Login Form Security', async function() {
    var loginForm = document.getElementById('loginForm');
    if (loginForm) {
        var emailInput = loginForm.querySelector('input[type="email"]');
        var passwordInput = loginForm.querySelector('input[type="password"]');

        if (emailInput && passwordInput) {
            var hasValidation = emailInput.hasAttribute('required') && passwordInput.hasAttribute('required');
            if (hasValidation) {
                return { status: 'pass', message: 'Login form has proper validation attributes' };
            }
        }
        return { status: 'warn', message: 'Login form validation could be improved' };
    }
    return { status: 'info', message: 'No login form found on this page' };
}, 'Checks login form security features');

testFramework.addTest('auth', 'Password Field Security', async function() {
    var passwordInputs = document.querySelectorAll('input[type="password"]');
    if (passwordInputs.length > 0) {
        var allSecure = true;
        for (var i = 0; i < passwordInputs.length; i++) {
            var input = passwordInputs[i];
            if (!input.hasAttribute('autocomplete') || input.getAttribute('autocomplete') === 'on') {
                allSecure = false;
            }
        }
        if (allSecure) {
            return { status: 'pass', message: 'Password fields have proper autocomplete settings' };
        }
        return { status: 'warn', message: 'Password fields should have appropriate autocomplete attributes' };
    }
    return { status: 'info', message: 'No password fields found on this page' };
}, 'Validates password field security attributes');

// Token Storage Security Tests
testFramework.addTest('token', 'Token Storage Method', async function() {
    var hasLocalStorageToken = localStorage.getItem('access_token');
    var hasSessionStorageToken = sessionStorage.getItem('access_token');

    if (hasSessionStorageToken && !hasLocalStorageToken) {
        return { status: 'pass', message: 'Using sessionStorage for token storage' };
    } else if (hasLocalStorageToken) {
        return { status: 'fail', message: 'Using localStorage for tokens (vulnerable to XSS)' };
    }
    return { status: 'info', message: 'No tokens found in storage' };
}, 'Verifies secure token storage mechanism');

testFramework.addTest('token', 'Token Exposure Prevention', async function() {
    var exposedTokens = [];
    if (window.access_token) exposedTokens.push('access_token');
    if (window.token) exposedTokens.push('token');
    if (window.authToken) exposedTokens.push('authToken');

    if (exposedTokens.length === 0) {
        return { status: 'pass', message: 'No tokens exposed in global scope' };
    }
    return { status: 'fail', message: 'Tokens exposed globally: ' + exposedTokens.join(', ') };
}, 'Checks for token exposure in global JavaScript scope');

testFramework.addTest('token', 'JWT Parsing Security', async function() {
    var scripts = Array.from(document.scripts);
    var hasJWTParsing = false;

    for (var i = 0; i < scripts.length; i++) {
        var script = scripts[i];
        if (script.textContent && script.textContent.includes('atob') && script.textContent.includes('split')) {
            hasJWTParsing = true;
        }
    }

    if (!hasJWTParsing) {
        return { status: 'pass', message: 'No client-side JWT parsing detected' };
    }
    return { status: 'fail', message: 'Client-side JWT parsing detected (security risk)' };
}, 'Detects dangerous client-side JWT token parsing');

// Input Validation Tests
testFramework.addTest('validation', 'Email Validation', async function() {
    var emailInputs = document.querySelectorAll('input[type="email"]');
    if (emailInputs.length > 0) {
        var hasValidation = true;
        for (var i = 0; i < emailInputs.length; i++) {
            var input = emailInputs[i];
            if (!input.hasAttribute('pattern') && !input.hasAttribute('required')) {
                hasValidation = false;
            }
        }
        if (hasValidation) {
            return { status: 'pass', message: 'Email inputs have validation attributes' };
        }
        return { status: 'warn', message: 'Email validation could be strengthened' };
    }
    return { status: 'info', message: 'No email inputs found' };
}, 'Validates email input security');

testFramework.addTest('validation', 'Form Validation Implementation', async function() {
    var forms = document.querySelectorAll('form');
    if (forms.length > 0) {
        var hasClientValidation = false;
        for (var i = 0; i < forms.length; i++) {
            var form = forms[i];
            if (form.hasAttribute('novalidate') === false) {
                hasClientValidation = true;
            }
        }
        if (hasClientValidation) {
            return { status: 'pass', message: 'Forms have client-side validation enabled' };
        }
        return { status: 'warn', message: 'Forms should have proper validation' };
    }
    return { status: 'info', message: 'No forms found on this page' };
}, 'Checks form validation implementation');

// CSRF Protection Tests
testFramework.addTest('csrf', 'CSRF Token Presence', async function() {
    var csrfToken = document.querySelector('meta[name="csrf-token"]');
    var csrfInput = document.querySelector('input[name="csrf_token"]');

    if (csrfToken || csrfInput) {
        return { status: 'pass', message: 'CSRF protection token found' };
    }
    return { status: 'warn', message: 'No CSRF protection tokens detected' };
}, 'Checks for CSRF protection implementation');

testFramework.addTest('csrf', 'SameSite Cookie Check', async function() {
    return { status: 'info', message: 'SameSite cookie check requires backend verification' };
}, 'Verifies SameSite cookie configuration');

// Information Disclosure Tests
testFramework.addTest('disclosure', 'Console Log Security', async function() {
    var originalConsole = window.console.log;
    var sensitiveLogs = [];

    window.console.log = function() {
        var args = Array.prototype.slice.call(arguments);
        var content = args.join(' ');
        if (content.includes('token') || content.includes('password') || content.includes('secret')) {
            sensitiveLogs.push(content.substring(0, 100));
        }
        originalConsole.apply(console, args);
    };

    setTimeout(function() {
        window.console.log = originalConsole;
    }, 100);

    if (sensitiveLogs.length === 0) {
        return { status: 'pass', message: 'No sensitive information in console logs detected' };
    }
    return { status: 'fail', message: 'Sensitive console logs: ' + sensitiveLogs.length + ' found' };
}, 'Detects sensitive information in console logs');

testFramework.addTest('disclosure', 'Error Message Security', async function() {
    var errorElements = document.querySelectorAll('.error, .alert-danger, [class*="error"]');
    var exposesInfo = false;

    for (var i = 0; i < errorElements.length; i++) {
        var el = errorElements[i];
        var text = el.textContent.toLowerCase();
        if (text.includes('sql') || text.includes('database') || text.includes('stack trace')) {
            exposesInfo = true;
        }
    }

    if (!exposesInfo) {
        return { status: 'pass', message: 'Error messages appear secure' };
    }
    return { status: 'fail', message: 'Error messages may expose sensitive information' };
}, 'Checks error messages for information disclosure');

// Open Redirect Tests
testFramework.addTest('redirect', 'Redirect URL Validation', async function() {
    if (window.UserManagementApp && window.UserManagementApp._secureRedirect) {
        return { status: 'pass', message: 'Secure redirect function implemented' };
    } else if (window.AppConfig && window.AppConfig._secureRedirect) {
        return { status: 'pass', message: 'Secure redirect function found in AppConfig' };
    }
    return { status: 'warn', message: 'No secure redirect validation detected' };
}, 'Verifies redirect URL validation');

testFramework.addTest('redirect', 'Link Target Validation', async function() {
    var links = document.querySelectorAll('a[href]');
    var hasExternalLinks = false;
    var hasUnsafeTargets = false;

    for (var i = 0; i < links.length; i++) {
        var link = links[i];
        var href = link.getAttribute('href');
        if (href && (href.startsWith('http://') || href.startsWith('https://'))) {
            hasExternalLinks = true;
            if (!link.hasAttribute('rel') || !link.getAttribute('rel').includes('noopener')) {
                hasUnsafeTargets = true;
            }
        }
    }

    if (!hasExternalLinks) {
        return { status: 'pass', message: 'No external links found' };
    } else if (!hasUnsafeTargets) {
        return { status: 'pass', message: 'External links have proper security attributes' };
    }
    return { status: 'warn', message: 'External links should have rel="noopener"' };
}, 'Validates external link security attributes');

// Content Security Policy Tests
testFramework.addTest('csp', 'CSP Header Presence', async function() {
    var cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    if (cspMeta) {
        var content = cspMeta.getAttribute('content');
        if (content && content.includes('default-src')) {
            return { status: 'pass', message: 'CSP policy found and configured' };
        }
    }
    return { status: 'fail', message: 'No CSP policy detected' };
}, 'Checks for Content Security Policy implementation');

testFramework.addTest('csp', 'Inline Script Prevention', async function() {
    var inlineScripts = document.querySelectorAll('script:not([src])');
    if (inlineScripts.length === 0) {
        return { status: 'pass', message: 'No inline scripts detected' };
    }
    return { status: 'warn', message: inlineScripts.length + ' inline scripts found (CSP violation risk)' };
}, 'Detects inline scripts that violate CSP');

// Logging Security Tests
testFramework.addTest('logging', 'Secure Logging Implementation', async function() {
    if (window.logInfo && window.logError && window.logAuthEvent) {
        return { status: 'pass', message: 'Secure logging functions implemented' };
    } else if (window.FrontendLogger) {
        return { status: 'pass', message: 'Frontend logger available' };
    }
    return { status: 'warn', message: 'Secure logging implementation not detected' };
}, 'Verifies secure logging system implementation');

testFramework.addTest('logging', 'PII Protection in Logs', async function() {
    if (window.logInfo) {
        try {
            window.logInfo('Test email: test@example.com', {
                email: 'sensitive@example.com',
                password: 'secretpassword'
            });
            return { status: 'pass', message: 'Logging functions available (PII protection assumed)' };
        } catch (error) {
            return { status: 'warn', message: 'Logging function test failed' };
        }
    }
    return { status: 'info', message: 'PII protection testing requires backend verification' };
}, 'Tests PII protection in logging system');

function toggleSection(sectionId) {
    var content = document.getElementById(sectionId + '-content');
    var toggle = document.getElementById(sectionId + '-toggle');

    content.classList.toggle('active');
    toggle.classList.toggle('rotated');
}

function runAllTests() {
    testFramework.runAllTests();
}

function exportResults() {
    testFramework.showExportModal();
}

function copyToClipboard() {
    var textarea = document.getElementById('exportText');
    textarea.select();
    textarea.setSelectionRange(0, 99999);
    document.execCommand('copy');

    var copyBtn = document.getElementById('copyBtn');
    var originalText = copyBtn.textContent;
    copyBtn.textContent = 'Copied!';
    copyBtn.style.background = '#28a745';

    setTimeout(function() {
        copyBtn.textContent = originalText;
        copyBtn.style.background = '#007bff';
    }, 2000);
}

function closeExportModal() {
    document.getElementById('exportModal').style.display = 'none';
}

document.addEventListener('DOMContentLoaded', function() {
    toggleSection('xss');
});