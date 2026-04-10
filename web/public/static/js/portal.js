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
let ws = null;
let wsReconnectTimer = null;

function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${proto}//${location.host}/ws`);

  ws.onopen = () => {
    console.log('[wicket] WS connected');
  };

  ws.onmessage = (evt) => {
    try {
      const event = JSON.parse(evt.data);
      handleServerEvent(event);
    } catch (e) { /* not JSON */ }
  };

  ws.onclose = () => {
    console.log('[wicket] WS disconnected, reconnecting in 5s...');
    wsReconnectTimer = setTimeout(connectWS, 5000);
  };

  ws.onerror = () => {
    ws.close();
  };
}

function handleServerEvent(event) {
  console.log('[wicket] event:', event.type, event);
  switch (event.type) {
    case 'device.approved':
      htmx.ajax('GET', '/', { target: '#device-list', swap: 'innerHTML', select: '#device-list' });
      showToast('Your device has been approved!', 'success');
      break;
    case 'device.rejected':
      htmx.ajax('GET', '/', { target: '#device-list', swap: 'innerHTML', select: '#device-list' });
      showToast('A device request was rejected.', 'warning');
      break;
    case 'session.expired':
    case 'session.revoked':
      htmx.ajax('GET', '/', { target: '#device-list', swap: 'innerHTML', select: '#device-list' });
      break;
    case 'peer.added':
      showToast('VPN session is now active', 'success');
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
    zIndex: '1000', maxWidth: '360px',
    animation: 'slideUp 0.25s ease',
  });
  document.body.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  startCountdowns();
  document.body.addEventListener('htmx:afterSwap', startCountdowns);
  connectWS();
});