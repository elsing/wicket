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

// ── Live countdown timers ─────────────────────────────────────────────────────
// Run a single interval that updates all active session badges every second.
function startCountdowns() {
  // Clear any existing interval
  if (window._countdownInterval) clearInterval(window._countdownInterval);
  
  window._countdownInterval = setInterval(() => {
    document.querySelectorAll('.session-badge[data-expires-at]').forEach(el => {
      const expiresAt = new Date(el.dataset.expiresAt);
      const remaining = expiresAt - Date.now();
      if (remaining <= 0) {
        el.textContent = 'Session expired';
        el.className = el.className.replace('badge-success', 'badge-error');
        el.removeAttribute('data-expires-at');
        refreshDeviceList();
      } else {
        const h = Math.floor(remaining / 3600000);
        const m = Math.floor((remaining % 3600000) / 60000);
        const s = Math.floor((remaining % 60000) / 1000);
        if (h > 0) {
          el.textContent = `Active · ${h}h ${m}m`;
          el.style.color = '';
          el.style.background = '';
        } else if (m >= 5) {
          el.textContent = `Active · ${m}m`;
          el.style.color = '';
          el.style.background = '';
        } else if (m > 0) {
          el.textContent = `Active · ${m}m ${s}s`;
          // Orange warning under 5 minutes
          el.style.background = 'var(--warning-light)';
          el.style.color = 'var(--warning-text)';
        } else {
          el.textContent = `Active · ${s}s`;
          // Red under 1 minute
          el.style.background = 'var(--error-light)';
          el.style.color = 'var(--error-text)';
        }
      }
    });
  }, 1000);
}

function refreshDeviceList() {
  htmx.ajax('GET', '/', { target: '#device-list', swap: 'innerHTML', select: '#device-list' });
}

// ── WebSocket ─────────────────────────────────────────────────────────────────
let ws = null;

function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${proto}//${location.host}/ws`);

  ws.onopen = () => console.log('[wicket] WS connected');

  ws.onmessage = (evt) => {
    try {
      const event = JSON.parse(evt.data);
      handleServerEvent(event);
    } catch (e) {}
  };

  ws.onclose = () => {
    console.log('[wicket] WS disconnected, reconnecting...');
    setTimeout(connectWS, 5000);
  };

  ws.onerror = () => ws.close();
}

function handleServerEvent(event) {
  console.log('[wicket] event:', event.type);
  switch (event.type) {
    case 'device.approved':
      refreshDeviceList();
      showToast('Your device has been approved — you can now activate it', 'success');
      break;
    case 'device.rejected':
      refreshDeviceList();
      showToast('A device was removed', 'warning');
      break;
    case 'session.created':
    case 'session.expired':
    case 'session.revoked':
      refreshDeviceList();
      break;
    case 'peer.added':
      showToast('VPN session active — tunnel is up', 'success');
      break;
    case 'peer.removed':
      refreshDeviceList();
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
  });
  document.body.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s';
    setTimeout(() => toast.remove(), 300);
  }, 5000);
}

// ── QR Code ───────────────────────────────────────────────────────────────────
// Uses qrcodejs loaded from CDN (added in template head)
function toggleQR(btn) {
  const container = document.getElementById('qr-container');
  if (container.style.display !== 'none') {
    container.style.display = 'none';
    return;
  }

  const config = btn.dataset.config;
  const canvas = document.getElementById('qr-canvas');

  // Use qrcode.js library to render to canvas
  if (typeof QRCode === 'undefined') {
    // Fallback: encode as data URI and use img src via server
    container.innerHTML = '<p style="color:var(--error-text)">QR library not loaded</p>';
    container.style.display = 'block';
    return;
  }

  canvas.innerHTML = '';
  new QRCode(canvas, {
    text: config,
    width: 220,
    height: 220,
    colorDark: '#000000',
    colorLight: '#ffffff',
    correctLevel: QRCode.CorrectLevel.M,
  });
  container.style.display = 'block';
}

function markDownloaded(link) {
  setTimeout(() => {
    const done = link.closest('.config-download').querySelector('.config-done');
    if (done) done.style.display = 'block';
  }, 500);
}

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  startCountdowns();
  // Restart countdowns after any HTMX swap (new badges may have appeared)
  document.body.addEventListener('htmx:afterSwap', startCountdowns);
  connectWS();
});
