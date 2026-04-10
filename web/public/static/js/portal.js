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
    btn.innerHTML = '✓ Copied!';
    btn.disabled = true;
    setTimeout(() => { btn.innerHTML = original; btn.disabled = false; }, 2000);
  }).catch(() => alert('Could not copy — please select and copy manually.'));
}

// ── QR Code ───────────────────────────────────────────────────────────────────
function toggleQR(btn) {
  const container = document.getElementById('qr-container');
  if (container.style.display !== 'none') {
    container.style.display = 'none';
    return;
  }
  const config = btn.dataset.config;
  const canvas = document.getElementById('qr-canvas');
  canvas.innerHTML = '';
  if (typeof QRCode !== 'undefined') {
    new QRCode(canvas, {
      text: config, width: 220, height: 220,
      colorDark: '#000', colorLight: '#fff',
      correctLevel: QRCode.CorrectLevel.M,
    });
  }
  container.style.display = 'block';
}

// ── Live countdown timers ─────────────────────────────────────────────────────
function startCountdowns() {
  if (window._countdownInterval) clearInterval(window._countdownInterval);
  window._countdownInterval = setInterval(tickCountdowns, 1000);
  tickCountdowns(); // immediate first tick
}

function tickCountdowns() {
  document.querySelectorAll('.session-badge[data-expires-at]').forEach(el => {
    const expiresAt = new Date(el.dataset.expiresAt);
    const remaining = expiresAt - Date.now();
    if (remaining <= 0) {
      el.textContent = 'Session expired';
      el.classList.remove('badge-success');
      el.classList.add('badge-muted');
      el.removeAttribute('data-expires-at');
      refreshDeviceList();
      return;
    }
    const h = Math.floor(remaining / 3600000);
    const m = Math.floor((remaining % 3600000) / 60000);
    const s = Math.floor((remaining % 60000) / 1000);
    if (h > 0) {
      el.textContent = `Active · ${h}h ${m}m`;
      el.style.background = '';
      el.style.color = '';
    } else if (m >= 5) {
      el.textContent = `Active · ${m}m ${s}s`;
      el.style.background = '';
      el.style.color = '';
    } else if (m > 0) {
      el.textContent = `Active · ${m}m ${s}s`;
      el.style.background = 'var(--warning-light)';
      el.style.color = 'var(--warning-text)';
    } else {
      el.textContent = `Active · ${s}s`;
      el.style.background = 'var(--error-light)';
      el.style.color = 'var(--error-text)';
    }
  });
}

// ── Device list refresh ───────────────────────────────────────────────────────
function refreshDeviceList() {
  const list = document.getElementById('device-list');
  if (!list) return;
  htmx.ajax('GET', '/', { target: '#device-list', swap: 'innerHTML', select: '#device-list' });
}

// ── WebSocket ─────────────────────────────────────────────────────────────────
let ws = null;
let wsReconnect = null;

function connectWS() {
  if (wsReconnect) { clearTimeout(wsReconnect); wsReconnect = null; }
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${proto}//${location.host}/ws`);

  ws.onopen = () => console.log('[wicket] WS connected');

  ws.onmessage = (evt) => {
    try { handleEvent(JSON.parse(evt.data)); } catch(e) {}
  };

  ws.onclose = () => {
    console.log('[wicket] WS disconnected, reconnecting in 5s...');
    wsReconnect = setTimeout(connectWS, 5000);
  };

  ws.onerror = () => ws.close();
}

function handleEvent(event) {
  console.log('[wicket]', event.type, event);
  switch (event.type) {
    case 'device.created':
      // New device was just added — refresh so it appears in the list
      refreshDeviceList();
      break;
    case 'device.approved':
      refreshDeviceList();
      showToast('Your device has been approved!', 'success');
      break;
    case 'device.rejected':
    case 'peer.removed':
      refreshDeviceList();
      break;
    case 'session.created':
      refreshDeviceList();
      showToast('VPN session activated', 'success');
      break;
    case 'session.revoked':
    case 'session.expired':
      refreshDeviceList();
      break;
    case 'peer.added':
      refreshDeviceList();
      showToast('VPN tunnel is up', 'success');
      break;
  }
}

// ── Toast ─────────────────────────────────────────────────────────────────────
function showToast(message, type = 'info') {
  const colors = {
    success: { bg: 'var(--success-light)', color: 'var(--success-text)' },
    warning: { bg: 'var(--warning-light)', color: 'var(--warning-text)' },
    error:   { bg: 'var(--error-light)',   color: 'var(--error-text)' },
    info:    { bg: 'var(--primary-light)', color: 'var(--primary)' },
  };
  const c = colors[type] || colors.info;
  const toast = Object.assign(document.createElement('div'), { textContent: message });
  Object.assign(toast.style, {
    position: 'fixed', bottom: '24px', right: '24px', padding: '14px 20px',
    borderRadius: '10px', fontSize: '14px', fontWeight: '500',
    background: c.bg, color: c.color, boxShadow: '0 8px 24px rgba(0,0,0,.15)',
    zIndex: '1000', maxWidth: '360px', transition: 'opacity 0.3s',
  });
  document.body.appendChild(toast);
  setTimeout(() => { toast.style.opacity = '0'; setTimeout(() => toast.remove(), 300); }, 4500);
}

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  startCountdowns();
  document.body.addEventListener('htmx:afterSwap', startCountdowns);
  connectWS();
});