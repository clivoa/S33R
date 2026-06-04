(function () {
  const THEME_KEY = 's33r-theme';
  const THEME_VALUES = new Set(['light', 'dark']);

  function getSystemTheme() {
    try {
      return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
        ? 'dark'
        : 'light';
    } catch {
      return 'light';
    }
  }

  function getSavedTheme() {
    try {
      const saved = localStorage.getItem(THEME_KEY);
      return THEME_VALUES.has(saved) ? saved : null;
    } catch {
      return null;
    }
  }

  function resolveTheme() {
    return getSavedTheme() || getSystemTheme();
  }

  function applyTheme(theme, persist = true) {
    const nextTheme = THEME_VALUES.has(theme) ? theme : 'light';
    document.documentElement.setAttribute('data-theme', nextTheme);
    document.documentElement.style.colorScheme = nextTheme;

    if (persist) {
      try {
        localStorage.setItem(THEME_KEY, nextTheme);
      } catch {}
    }

    updateThemeToggleUI(nextTheme);
    window.dispatchEvent(new CustomEvent('s33r:themechange', { detail: { theme: nextTheme } }));
  }

  function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme') || resolveTheme();
    applyTheme(current === 'dark' ? 'light' : 'dark');
  }

  function createThemeToggle() {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'theme-toggle';
    btn.id = 'theme-toggle';
    btn.setAttribute('aria-label', 'Toggle light and dark theme');
    btn.innerHTML = [
      '<span class="theme-toggle-icon" aria-hidden="true">◐</span>',
      '<span class="theme-toggle-label">Theme</span>'
    ].join('');

    btn.addEventListener('click', toggleTheme);
    return btn;
  }

  function updateThemeToggleUI(theme) {
    const btn = document.getElementById('theme-toggle');
    if (!btn) return;
    btn.dataset.theme = theme;
    btn.title = theme === 'dark' ? 'Dark theme active (click for light)' : 'Light theme active (click for dark)';
    btn.setAttribute('aria-pressed', theme === 'dark' ? 'true' : 'false');
    const label = btn.querySelector('.theme-toggle-label');
    if (label) label.textContent = theme === 'dark' ? 'Dark' : 'Light';
    const icon = btn.querySelector('.theme-toggle-icon');
    if (icon) icon.textContent = theme === 'dark' ? '☾' : '☀';
  }

  function ensureThemeToggle() {
    const nav = document.querySelector('.minimal-navbar');
    if (!nav || document.getElementById('theme-toggle')) return;
    nav.appendChild(createThemeToggle());
    updateThemeToggleUI(document.documentElement.getAttribute('data-theme') || resolveTheme());
  }

  function toast(message, ms) {
    if (!message) return;
    const existing = document.querySelector('.ui-toast');
    if (existing) existing.remove();

    const el = document.createElement('div');
    el.className = 'ui-toast';
    el.textContent = message;
    document.body.appendChild(el);

    setTimeout(() => {
      el.remove();
    }, typeof ms === 'number' ? ms : 1600);
  }

  async function copyText(text, okMessage) {
    if (!text) return false;
    try {
      await navigator.clipboard.writeText(text);
      toast(okMessage || 'Copied');
      return true;
    } catch {
      toast('Copy failed');
      return false;
    }
  }

  function downloadText(filename, text, mime) {
    const blob = new Blob([text], { type: mime || 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function initGlobalHotkeys() {
    document.addEventListener('keydown', (e) => {
      if (e.defaultPrevented) return;
      if (e.key.toLowerCase() === 't' && e.shiftKey && !e.ctrlKey && !e.metaKey && !e.altKey) {
        const tag = document.activeElement && document.activeElement.tagName;
        if (tag && ['INPUT', 'TEXTAREA', 'SELECT'].includes(tag)) return;
        e.preventDefault();
        toggleTheme();
      }
    });
  }

  function init() {
    applyTheme(resolveTheme(), false);
    ensureThemeToggle();
    initGlobalHotkeys();

    try {
      const media = window.matchMedia('(prefers-color-scheme: dark)');
      media.addEventListener('change', () => {
        if (!getSavedTheme()) {
          applyTheme(getSystemTheme(), false);
        }
      });
    } catch {}
  }

  window.S33R_UI = {
    applyTheme,
    toggleTheme,
    toast,
    copyText,
    downloadText,
    ensureThemeToggle,
    getTheme: () => document.documentElement.getAttribute('data-theme') || resolveTheme(),
  };

  // Apply as early as possible to reduce theme flash.
  try {
    const initialTheme = resolveTheme();
    document.documentElement.setAttribute('data-theme', initialTheme);
    document.documentElement.style.colorScheme = initialTheme;
  } catch {}

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
