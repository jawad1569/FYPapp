/* ========================================
   WAZUHBOT — Auth Page Logic
   ======================================== */

import { initTheme } from './theme.js';

const API_BASE  = '/api/auth';
const TOKEN_KEY = 'wazuhbot-token';
const USER_KEY  = 'wazuhbot-user';

/* ── Dev bypass: set to false to use real backend auth ── */
const DEV_MODE = false;

const MOCK_USER = {
  id:           'dev-001',
  fullName:     'Dev User',
  email:        'dev@wazuhbot.local',
  organization: 'Dev Org',
  wazuhIp:      '127.0.0.1',
};

/* ── Boot ── */
document.addEventListener('DOMContentLoaded', () => {
  initTheme();

  // If already logged in, go to chat
  if (localStorage.getItem(TOKEN_KEY)) {
    window.location.href = '/';
    return;
  }

  const loginForm  = document.getElementById('loginForm');
  const signupForm = document.getElementById('signupForm');

  if (loginForm)  loginForm.addEventListener('submit', handleLogin);
  if (signupForm) signupForm.addEventListener('submit', handleSignup);

  // Password visibility toggle
  const toggleBtn = document.getElementById('togglePassword');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      const pwInput = document.getElementById('password');
      const isHidden = pwInput.type === 'password';
      pwInput.type = isHidden ? 'text' : 'password';
      toggleBtn.title = isHidden ? 'Hide password' : 'Show password';
    });
  }
});

/* ── Login handler ── */
async function handleLogin(e) {
  e.preventDefault();
  clearError();

  const email    = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;

  // Client-side checks
  if (!email || !password) {
    return showError('Please fill in all fields.');
  }

  if (!isValidEmail(email)) {
    return showError('Please enter a valid email address.');
  }

  setLoading(true);

  // ── Dev bypass ──────────────────────────────────
  if (DEV_MODE) {
    localStorage.setItem(TOKEN_KEY, 'dev-token');
    localStorage.setItem(USER_KEY, JSON.stringify({ ...MOCK_USER, email }));
    window.location.href = '/2fa.html';
    return;
  }
  // ────────────────────────────────────────────────

  try {
    const res = await fetch(`${API_BASE}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.message || 'Login failed.');
    }

    localStorage.setItem(TOKEN_KEY, data.token);
    localStorage.setItem(USER_KEY, JSON.stringify(data.user));
    window.location.href = '/2fa.html';
  } catch (err) {
    showError(err.message);
  } finally {
    setLoading(false);
  }
}

/* ── Signup handler ── */
async function handleSignup(e) {
  e.preventDefault();
  clearError();

  const fullName        = document.getElementById('fullName').value.trim();
  const email           = document.getElementById('email').value.trim();
  const password        = document.getElementById('password').value;
  const confirmPassword = document.getElementById('confirmPassword').value;
  const organization    = document.getElementById('organization')?.value.trim() || '';
  const wazuhIp         = document.getElementById('wazuhIp')?.value.trim()        || '';
  const wazuhIndexerIp  = document.getElementById('wazuhIndexerIp')?.value.trim() || '';
  const idxUser         = document.getElementById('idxUser')?.value.trim()        || '';
  const idxPassword     = document.getElementById('idxPassword')?.value           || '';
  const apiUser         = document.getElementById('apiUser')?.value.trim()        || '';
  const apiPassword     = document.getElementById('apiPassword')?.value           || '';

  // Client-side checks
  if (!fullName || !email || !password || !confirmPassword) {
    return showError('Please fill in all required fields.');
  }
  if (fullName.length < 2) {
    return showError('Name must be at least 2 characters.');
  }
  if (!isValidEmail(email)) {
    return showError('Please enter a valid email address.');
  }
  if (password.length < 8) {
    return showError('Password must be at least 8 characters.');
  }
  if (password !== confirmPassword) {
    return showError('Passwords do not match.');
  }
  if (!wazuhIp) {
    return showError('Wazuh IP / Hostname is required.');
  }
  if (!idxUser || !idxPassword) {
    return showError('Indexer username and password are required.');
  }
  if (!apiUser || !apiPassword) {
    return showError('Manager API username and password are required.');
  }

  setLoading(true);

  // ── Dev bypass ──────────────────────────────────
  if (DEV_MODE) {
    localStorage.setItem(TOKEN_KEY, 'dev-token');
    localStorage.setItem(USER_KEY, JSON.stringify({ ...MOCK_USER, fullName, email, organization, wazuhIp }));
    window.location.href = '/2fa.html';
    return;
  }
  // ────────────────────────────────────────────────

  try {
    const res = await fetch(`${API_BASE}/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        fullName, email, password, confirmPassword, organization,
        wazuhIp,
        wazuhIndexerIp,
        indexerUser:     idxUser,
        indexerPassword: idxPassword,
        apiUser,
        apiPassword,
      }),
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.message || 'Signup failed.');
    }

    localStorage.setItem(TOKEN_KEY, data.token);
    localStorage.setItem(USER_KEY, JSON.stringify(data.user));
    window.location.href = '/2fa.html';
  } catch (err) {
    showError(err.message);
  } finally {
    setLoading(false);
  }
}

/* ── Helpers ── */

function showError(msg) {
  const el = document.getElementById('authError');
  if (el) {
    el.textContent = msg;
    el.classList.add('visible');
  }
}

function clearError() {
  const el = document.getElementById('authError');
  if (el) {
    el.textContent = '';
    el.classList.remove('visible');
  }
}

function setLoading(loading) {
  const btn = document.getElementById('submitBtn');
  if (btn) {
    btn.classList.toggle('loading', loading);
    btn.disabled = loading;
  }
}

function isValidEmail(email) {
  return /^\S+@\S+\.\S+$/.test(email);
}
