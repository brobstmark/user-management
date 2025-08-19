>
  // Uses cookie-based session (no localStorage token).
  // Adds CSRF header only for POSTs.
  const API_BASE_URL = 'http://localhost:8000/api/v1';

  function getCookie(name) {
    return document.cookie
      .split('; ')
      .find(row => row.startsWith(name + '='))?.split('=')[1];
  }

  async function getCsrfToken() {
    let token = getCookie('csrftoken');
    if (token) return token;
    try {
      const res = await fetch(`${API_BASE_URL}/auth/csrf-token`, { credentials: 'include' });
      if (!res.ok) return null;
      const data = await res.json().catch(() => ({}));
      token = data.csrf_token || getCookie('csrftoken') || null;
      return token;
    } catch {
      return null;
    }
  }

  async function apiGet(path) {
    return fetch(`${API_BASE_URL}${path}`, { credentials: 'include' });
  }

  async function apiPost(path, body) {
    const csrf = await getCsrfToken();
    const headers = { 'Content-Type': 'application/json' };
    if (csrf) headers['X-CSRF-Token'] = csrf;
    return fetch(`${API_BASE_URL}${path}`, {
      method: 'POST',
      headers,
      credentials: 'include',
      body: body ? JSON.stringify(body) : null
    });
  }

  function redirectToLoginOnce() {
    if (sessionStorage.getItem('redirLogin')) return;
    sessionStorage.setItem('redirLogin', '1');
    window.location.href = '../auth/login.html';
  }

  async function checkAuthAndLoadUser() {
    // 1) Check auth
    const authRes = await apiGet('/auth/auth-status');
    if (!authRes.ok) {
      redirectToLoginOnce();
      return;
    }

    // 2) Load user profile (no Authorization header needed)
    try {
      const response = await apiGet('/users/me');
      if (response.status === 401) {
        redirectToLoginOnce();
        return;
      }
      if (!response.ok) throw new Error('profile_load_failed');
      const user = await response.json();

      // Update welcome section
      document.getElementById('userName').textContent =
        [user.first_name, user.last_name].filter(Boolean).join(' ') || user.username || 'User';
      document.getElementById('userEmail').textContent = user.email || '—';

      // Update stats (fill in what you want shown)
      document.getElementById('lastLogin').textContent =
        user.last_login ? new Date(user.last_login).toLocaleString() : '—';
      document.getElementById('memberSince').textContent =
        user.created_at ? new Date(user.created_at).toLocaleDateString() : '—';
      document.getElementById('profileStatus').textContent = user.is_active ? 'Active' : 'Inactive';

      // Render profile grid
      renderProfile(user);

      // Email verification status
      await checkEmailVerification();
    } catch (error) {
      // If anything fails, treat as not logged in
      redirectToLoginOnce();
    }
  }

  function renderProfile(user) {
    const grid = document.getElementById('profileGrid');
    const items = [
      ['First Name', user.first_name],
      ['Last Name', user.last_name],
      ['Username', user.username],
      ['Email', user.email],
      ['Language', user.language],
      ['Timezone', user.timezone]
    ];

    grid.innerHTML = items.map(([label, value]) => `
      <div class="profile-item">
        <div class="profile-label">${label}</div>
        <div class="profile-value">${value ?? '—'}</div>
      </div>
    `).join('');
  }

  async function checkEmailVerification() {
    try {
      const response = await apiGet('/auth/verification-status');
      if (!response.ok) return;
      const data = await response.json().catch(() => ({}));
      const statusElement = document.getElementById('emailStatus');

      if (data && data.is_verified === false) {
        statusElement.textContent = 'Pending ⏳';
        statusElement.style.color = '#ffc107';
      } else if (data && data.is_verified === true) {
        statusElement.textContent = 'Verified ✅';
        statusElement.style.color = '#28a745';
      } else {
        statusElement.textContent = 'Unknown';
      }
    } catch {
      document.getElementById('emailStatus').textContent = 'Unknown';
    }
  }

  async function resendVerification() {
    try {
      const response = await apiPost('/auth/send-verification');
      if (response.ok) {
        alert('✅ Verification email sent! Check your inbox.');
      } else {
        alert('❌ Failed to send verification email. Please try again.');
      }
    } catch {
      alert('❌ Network error. Please try again.');
    }
  }

  function editProfile() {
    window.location.href = '../profile.html';
  }

  function changePassword() {
    window.location.href = '../security.html';
  }

  async function logout() {
    try { await apiPost('/auth/logout'); } catch {}
    sessionStorage.removeItem('redirLogin');
    window.location.href = '../auth/login.html';
  }

  // Expose buttons used by your existing HTML
  window.editProfile = editProfile;
  window.changePassword = changePassword;
  window.resendVerification = resendVerification;
  window.logout = logout;

  // Boot
  window.addEventListener('load', () => {
    checkAuthAndLoadUser();
  });