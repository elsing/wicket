// Wicket public portal JS
// Uses window properties to survive HTMX swaps and script re-executions.

(function() { // IIFE prevents re-declaration errors

// ── Theme ─────────────────────────────────────────────────────────────────────
const stored = localStorage.getItem('theme');
if (stored) document.documentElement.setAttribute('data-theme', stored);

window.toggleTheme = function() {
  const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('theme', next);
};

// ── Copy config ───────────────────────────────────────────────────────────────
window.copyConfig = function(btn) {
  const config = btn.dataset.config;
  if (!config) return;
  navigator.clipboard.writeText(config).then(() => {
    const orig = btn.innerHTML;
    btn.innerHTML = '✓ Copied!';
    btn.disabled = true;
    setTimeout(() => { btn.innerHTML = orig; btn.disabled = false; }, 2000);
  }).catch(() => alert('Could not copy — select and copy manually.'));
};

// ── QR Code ───────────────────────────────────────────────────────────────────
window.toggleQR = function(btn) {
  const container = document.getElementById('qr-container');
  if (container.style.display !== 'none') { container.style.display = 'none'; return; }
  const el = document.getElementById('qr-canvas');
  el.innerHTML = ''; // clear previous QR
  if (typeof QRCode === 'undefined') {
    el.textContent = 'QR library not loaded';
    container.style.display = 'block';
    return;
  }
  try {
    new QRCode(el, {
      text: btn.dataset.config,
      width: 220,
      height: 220,
      colorDark: '#000000',
      colorLight: '#ffffff',
      correctLevel: QRCode.CorrectLevel.M,
    });
    container.style.display = 'block';
  } catch(e) {
    console.error('QR generation failed:', e);
    el.textContent = 'QR generation failed';
    container.style.display = 'block';
  }
};

// ── Live countdown timers ─────────────────────────────────────────────────────
function startCountdowns() {
  if (window._wicketCountdown) clearInterval(window._wicketCountdown);
  window._wicketCountdown = setInterval(tickCountdowns, 1000);
  tickCountdowns();
}

function tickCountdowns() {
  document.querySelectorAll('.session-badge[data-expires-at]').forEach(el => {
    const remaining = new Date(el.dataset.expiresAt) - Date.now();
    if (remaining <= 0) {
      el.textContent = 'Session expired';
      el.classList.replace('badge-success', 'badge-muted');
      el.removeAttribute('data-expires-at');
      refreshDeviceList();
      return;
    }
    const h = Math.floor(remaining / 3600000);
    const m = Math.floor((remaining % 3600000) / 60000);
    const s = Math.floor((remaining % 60000) / 1000);
    if (h > 0) {
      el.textContent = `Active · ${h}h ${m}m`;
      el.style.cssText = '';
    } else if (m >= 5) {
      el.textContent = `Active · ${m}m ${s}s`;
      el.style.cssText = '';
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

// ── Device list refresh (debounced) ──────────────────────────────────────────
// Debounce prevents cascade: multiple rapid WS events (session.created +
// peer.added) each triggering a refresh causes a loop. Wait 500ms and
// only do one refresh if multiple events arrive close together.
let _refreshTimer = null;
function refreshDeviceList() {
  if (!document.getElementById('device-list')) return;
  if (_refreshTimer) clearTimeout(_refreshTimer);
  _refreshTimer = setTimeout(() => {
    _refreshTimer = null;
    htmx.ajax('GET', '/', { target: '#device-list', swap: 'innerHTML', select: '#device-list' });
  }, 500);
}

// ── WebSocket — single persistent connection ──────────────────────────────────
function connectWS() {
  if (window.wicketWS && (window.wicketWS.readyState === WebSocket.OPEN ||
                           window.wicketWS.readyState === WebSocket.CONNECTING)) {
    return; // already connected
  }

  if (window.wicketWSReconnect) clearTimeout(window.wicketWSReconnect);

  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${proto}//${location.host}/ws`);
  window.wicketWS = ws;

  ws.onopen = () => {
    console.log('[wicket] WS connected');
    if (window.wicketWSKeepalive) clearInterval(window.wicketWSKeepalive);
    window.wicketWSKeepalive = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({type:'ping'}));
    }, 25000);
  };

  ws.onmessage = (evt) => {
    try {
      const event = JSON.parse(evt.data);
      if (event.type === 'ping') return;
      console.log('[wicket]', event.type, event);
      handleEvent(event);
    } catch(e) {}
  };

  ws.onclose = (e) => {
    console.log('[wicket] WS closed', e.code, '— reconnect in 5s');
    if (window.wicketWSKeepalive) clearInterval(window.wicketWSKeepalive);
    window.wicketWSReconnect = setTimeout(connectWS, 5000);
  };

  ws.onerror = () => ws.close();
}

function handleEvent(event) {
  console.log('[wicket] event:', event.type);
  switch (event.type) {
    case 'device.created':
    case 'device.approved':
      refreshDeviceList();
      if (event.type === 'device.approved') showToast('Your device has been approved!', 'success');
      break;
    case 'device.rejected':
    case 'peer.removed':
    case 'session.revoked':
    case 'session.expired':
      refreshDeviceList();
      break;
    case 'session.created':
    case 'peer.added':
      refreshDeviceList();
      if (event.type === 'peer.added') showToast('VPN tunnel is up', 'success');
      break;
  }
}

// ── Toast ─────────────────────────────────────────────────────────────────────
window.showToast = function(message, type = 'info') {
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
};

function showToast(msg, type) { window.showToast(msg, type); }

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  startCountdowns();
  connectWS();
});

document.body.addEventListener('htmx:afterSwap', () => {
  startCountdowns();
  connectWS(); // no-op if already connected
});

})(); // end IIFE