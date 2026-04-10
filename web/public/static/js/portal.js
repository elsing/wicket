// Wicket public portal JS

// ── Theme ─────────────────────────────────────────────────────────────────────
(function () {
  const stored = localStorage.getItem('theme');
  if (stored) document.documentElement.setAttribute('data-theme', stored);
})();

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme');
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('theme', next);
}

// ── Copy config ───────────────────────────────────────────────────────────────
function copyConfig(btn) {
  const config = btn.dataset.config;
  if (!config) return;
  navigator.clipboard.writeText(config).then(() => {
    const original = btn.innerHTML;
    btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg> Copied!`;
    btn.disabled = true;
    setTimeout(() => { btn.innerHTML = original; btn.disabled = false; }, 2000);
  }).catch(() => alert('Could not copy — please select and copy manually.'));
}

// ── Countdown timers ──────────────────────────────────────────────────────────
function startCountdowns() {
  document.querySelectorAll('[data-expires-at]').forEach(el => {
    updateCountdown(el, new Date(el.dataset.expiresAt));
  });
}

function updateCountdown(el, expiresAt) {
  const update = () => {
    const remaining = expiresAt - Date.now();
    if (remaining <= 0) {
      el.textContent = 'Expired';
      el.className = el.className.replace('badge-success', 'badge-muted');
      return;
    }
    const h = Math.floor(remaining / 3600000);
    const m = Math.floor((remaining % 3600000) / 60000);
    el.textContent = h > 0 ? `Active · ${h}h ${m}m` : `Active · ${m}m`;
  };
  update();
  const interval = setInterval(() => {
    if (!document.contains(el)) { clearInterval(interval); return; }
    update();
  }, 60000);
}

// ── WebSocket live updates ────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  startCountdowns();
  document.body.addEventListener('htmx:afterSwap', startCountdowns);
});

document.body.addEventListener('htmx:wsMessage', (evt) => {
  try {
    const event = JSON.parse(evt.detail.message);
    handleServerEvent(event);
  } catch (e) { /* not JSON */ }
});

function handleServerEvent(event) {
  switch (event.type) {
    case 'device.approved':
    case 'device.rejected':
      // Refresh the entire device list
      htmx.ajax('GET', '/', { target: '#device-list', swap: 'innerHTML', select: '#device-list > *' });
      showToast(event.type === 'device.approved' ? 'Your device has been approved!' : 'A device request was rejected.', 
                event.type === 'device.approved' ? 'success' : 'warning');
      break;

    case 'session.expired':
    case 'session.revoked':
      // Refresh device list so session status updates
      htmx.ajax('GET', '/', { target: '#device-list', swap: 'innerHTML', select: '#device-list > *' });
      break;

    case 'peer.added':
      showToast('VPN session is active', 'success');
      break;
  }
}

// ── Toast ─────────────────────────────────────────────────────────────────────
function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.textContent = message;
  const colors = {
    success: { bg: 'var(--success-light)', color: 'var(--success-text)' },
    warning: { bg: 'var(--warning-light)', color: 'var(--warning-text)' },
    error:   { bg: 'var(--error-light)',   color: 'var(--error-text)' },
    info:    { bg: 'var(--primary-light)', color: 'var(--primary)' },
  };
  const c = colors[type] || colors.info;
  Object.assign(toast.style, {
    position: 'fixed', bottom: '24px', right: '24px',
    padding: '14px 20px', borderRadius: '10px',
    fontSize: '14px', fontWeight: '500',
    background: c.bg, color: c.color,
    boxShadow: '0 8px 24px rgba(0,0,0,.15)',
    animation: 'slideUp 0.25s ease', zIndex: '1000', maxWidth: '360px',
  });
  document.body.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}