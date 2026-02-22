/* ========================================
   SETTINGS MODAL
   ======================================== */

import { setTheme } from './theme.js';

const modal          = document.getElementById('settingsModal');
const settingsBtn    = document.getElementById('settingsBtn');
const closeBtn       = document.getElementById('modalCloseBtn');
const themeButtons   = document.querySelectorAll('.theme-option');
const deleteAllBtn   = document.getElementById('deleteAllChatsBtn');

/** Initialise settings bindings. Pass a callback to handle "Delete All". */
export function initSettings({ onDeleteAll }) {
  settingsBtn.addEventListener('click', openSettings);
  closeBtn.addEventListener('click', closeSettings);

  // Close on overlay click
  modal.addEventListener('click', (e) => {
    if (e.target === modal) closeSettings();
  });

  // Close on Escape
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && modal.classList.contains('open')) {
      closeSettings();
    }
  });

  // Theme buttons
  themeButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      setTheme(btn.dataset.themeValue);
    });
  });

  // Delete all chats
  deleteAllBtn.addEventListener('click', () => {
    if (confirm('Are you sure you want to delete all chats? This cannot be undone.')) {
      onDeleteAll();
      closeSettings();
    }
  });
}

export function openSettings() {
  modal.classList.add('open');
}

export function closeSettings() {
  modal.classList.remove('open');
}
