/* ========================================
   THEME MANAGER
   ======================================== */

const STORAGE_KEY = 'wazuhbot-theme';

/**
 * Initialise theme from localStorage or system preference.
 */
export function initTheme() {
  const saved = localStorage.getItem(STORAGE_KEY);

  if (saved && saved !== 'system') {
    applyTheme(saved);
  } else {
    applySystemTheme();
  }

  updateToggleButtons(saved || 'system');

  // Listen for system preference changes
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    const current = localStorage.getItem(STORAGE_KEY);
    if (!current || current === 'system') {
      applySystemTheme();
    }
  });
}

/**
 * Set the theme and persist setting.
 * @param {'light' | 'dark' | 'system'} value
 */
export function setTheme(value) {
  localStorage.setItem(STORAGE_KEY, value);

  if (value === 'system') {
    applySystemTheme();
  } else {
    applyTheme(value);
  }

  updateToggleButtons(value);
}

/** @returns {'light' | 'dark'} */
export function getCurrentTheme() {
  return document.documentElement.getAttribute('data-theme') || 'dark';
}

/* ── helpers ── */

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
}

function applySystemTheme() {
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  applyTheme(prefersDark ? 'dark' : 'light');
}

function updateToggleButtons(active) {
  document.querySelectorAll('.theme-option').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.themeValue === active);
  });
}
