/* ========================================
   SETTINGS MODAL
   ======================================== */

import { setTheme } from './theme.js';

const modal          = document.getElementById('settingsModal');
const settingsBtn    = document.getElementById('settingsBtn');
const closeBtn       = document.getElementById('modalCloseBtn');
const themeButtons   = document.querySelectorAll('.theme-option');
const deleteAllBtn   = document.getElementById('deleteAllChatsBtn');

const API_BASE = window.location.hostname === 'localhost' ? 'http://localhost:5000/api' : '/api';
function authToken() { return localStorage.getItem('wazuhbot-token'); }

/** Initialise settings bindings. Pass a callback to handle "Delete All". */
export function initSettings({ onDeleteAll }) {
  settingsBtn.addEventListener('click', openSettings);
  closeBtn.addEventListener('click', closeSettings);

  modal.addEventListener('click', (e) => { if (e.target === modal) closeSettings(); });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && modal.classList.contains('open')) closeSettings();
  });

  themeButtons.forEach(btn => {
    btn.addEventListener('click', () => setTheme(btn.dataset.themeValue));
  });

  deleteAllBtn.addEventListener('click', () => {
    if (confirm('Are you sure you want to delete all chats? This cannot be undone.')) {
      onDeleteAll();
      closeSettings();
    }
  });

  // ── Wazuh credentials ──
  const wzIp      = document.getElementById('wz-ip');
  const wzIdxUser = document.getElementById('wz-idx-user');
  const wzIdxPass = document.getElementById('wz-idx-pass');
  const wzApiUser = document.getElementById('wz-api-user');
  const wzApiPass = document.getElementById('wz-api-pass');
  const wzResult  = document.getElementById('wzResult');
  const wzTestBtn = document.getElementById('wzTestBtn');
  const wzSaveBtn = document.getElementById('wzSaveBtn');

  // Pre-fill from cached profile
  try {
    const u = JSON.parse(localStorage.getItem('wazuhbot-user') || '{}');
    if (u.wazuhIp)   wzIp.value      = u.wazuhIp;
    if (u.wazuhUser) wzIdxUser.value = u.wazuhUser;
  } catch { /* ignore */ }

  function showResult(html) { wzResult.innerHTML = html; }

  function getFields() {
    return {
      wazuhIp:         wzIp.value.trim(),
      indexerUser:     wzIdxUser.value.trim(),
      indexerPassword: wzIdxPass.value,
      apiUser:         wzApiUser.value.trim(),
      apiPassword:     wzApiPass.value,
    };
  }

  wzTestBtn.addEventListener('click', async () => {
    const body = getFields();
    if (!body.wazuhIp) { showResult('<span class="cr-fail">Enter Wazuh IP first.</span>'); return; }
    wzTestBtn.disabled = true;
    showResult('<span class="cr-info">Testing…</span>');
    try {
      const res  = await fetch(`${API_BASE}/auth/test-wazuh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken()}` },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      const { indexer, manager } = data.results || {};
      const idxHtml = indexer
        ? (indexer.ok ? '<span class="cr-ok">✓ Indexer (9200) connected</span>' : `<span class="cr-fail">✗ Indexer: ${indexer.error}</span>`)
        : '<span class="cr-info">— Indexer not tested</span>';
      const mgrHtml = manager
        ? (manager.ok ? '<span class="cr-ok">✓ Manager API (55000) connected</span>' : `<span class="cr-fail">✗ Manager: ${manager.error}</span>`)
        : '<span class="cr-info">— Manager API not tested</span>';
      showResult(`${idxHtml}<br>${mgrHtml}`);
    } catch { showResult('<span class="cr-fail">Request failed. Is the backend running?</span>'); }
    finally   { wzTestBtn.disabled = false; }
  });

  wzSaveBtn.addEventListener('click', async () => {
    const body = getFields();
    if (!body.wazuhIp || !body.indexerUser || !body.indexerPassword) {
      showResult('<span class="cr-fail">IP, Indexer user, and password are required.</span>');
      return;
    }
    wzSaveBtn.disabled = true;
    showResult('<span class="cr-info">Saving…</span>');
    try {
      const res  = await fetch(`${API_BASE}/auth/wazuh-credentials`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken()}` },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Save failed');
      try {
        const u = JSON.parse(localStorage.getItem('wazuhbot-user') || '{}');
        u.wazuhIp   = body.wazuhIp;
        u.wazuhUser = body.indexerUser;
        localStorage.setItem('wazuhbot-user', JSON.stringify(u));
      } catch { /* ignore */ }
      showResult('<span class="cr-ok">✓ Saved. Refresh Sentinel to see live data.</span>');
    } catch (e) { showResult(`<span class="cr-fail">Error: ${e.message}</span>`); }
    finally     { wzSaveBtn.disabled = false; }
  });
}

export function openSettings() {
  modal.classList.add('open');
}

export function closeSettings() {
  modal.classList.remove('open');
}
