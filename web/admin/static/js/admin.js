// Wicket admin portal JS
// Uses window.wicketWS so the connection persists across HTMX partial swaps
// and script re-executions without "already declared" errors.

(function() { // IIFE prevents re-declaration errors on script reload

// ── Theme ─────────────────────────────────────────────────────────────────────
const stored = localStorage.getItem('theme');
if (stored) document.documentElement.setAttribute('data-theme', stored);

window.toggleTheme = function() {
  const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('theme', next);
};

// ── WebSocket — single persistent connection ──────────────────────────────────
// Stored on window so it survives HTMX swaps and script re-runs.
function connectWS() {
  // Already connected — do nothing
  if (window.wicketWS && (window.wicketWS.readyState === WebSocket.OPEN ||
                           window.wicketWS.readyState === WebSocket.CONNECTING)) {
    return;
  }

  if (window.wicketWSReconnect) { clearTimeout(window.wicketWSReconnect); }

  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${proto}//${location.host}/ws`);
  window.wicketWS = ws;

  ws.onopen = () => {
    console.log('[wicket admin] WS connected');
    document.querySelectorAll('.live-dot').forEach(d => d.style.background = 'var(--success)');
    // Client keepalive every 25s to survive proxy idle timeouts
    if (window.wicketWSKeepalive) clearInterval(window.wicketWSKeepalive);
    window.wicketWSKeepalive = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({type:'ping'}));
    }, 25000);
  };

  ws.onmessage = (evt) => {
    try {
      const event = JSON.parse(evt.data);
      if (event.type === 'ping') return; // ignore server pings
      console.log('[wicket admin]', event.type, event);
      handleEvent(event);
    } catch(e) {}
  };

  ws.onclose = (e) => {
    console.log('[wicket admin] WS closed', e.code, '— reconnect in 5s');
    if (window.wicketWSKeepalive) clearInterval(window.wicketWSKeepalive);
    document.querySelectorAll('.live-dot').forEach(d => d.style.background = 'var(--error)');
    window.wicketWSReconnect = setTimeout(connectWS, 5000);
  };

  ws.onerror = () => ws.close();
}

// ── Refresh helpers ───────────────────────────────────────────────────────────
function refreshAfterDeviceChange() {
  if (document.getElementById('dashboard-content')) {
    htmx.ajax('GET', '/dashboard/fragment', { target: '#dashboard-content', swap: 'innerHTML' });
    return;
  }
  if (document.getElementById('devices-tbody')) {
    // Fetch just the tbody rows - server detects HX-Request and returns fragment
    fetch('/devices', {
      headers: { 'HX-Request': 'true', 'HX-Target': 'devices-tbody' }
    })
    .then(r => r.text())
    .then(html => {
      const el = document.getElementById('devices-tbody');
      if (el) el.innerHTML = html;
    })
    .catch(e => console.warn('[wicket admin] devices refresh failed', e));
  }
}

function refreshAfterSessionChange() {
  if (document.getElementById('sessions-table')) {
    htmx.ajax('GET', '/sessions', { target: '#sessions-table', swap: 'innerHTML' });
  }
}

function handleEvent(event) {
  switch (event.type) {
    case 'device.created':
      refreshAfterDeviceChange();
      showToast('New device pending approval', 'warning');
      break;
    case 'device.approved':
      refreshAfterDeviceChange();
      showToast('Device approved', 'success');
      break;
    case 'device.rejected':
      refreshAfterDeviceChange();
      break;
    case 'session.created':
      refreshAfterSessionChange();
      break;
    case 'session.revoked':
    case 'session.expired':
      refreshAfterSessionChange();
      refreshAfterDeviceChange();
      break;
    case 'peer.added':
      showToast('WireGuard peer added', 'success');
      break;
    case 'peer.removed':
      showToast('WireGuard peer removed', 'info');
      break;
  }
}

// ── Metrics sparklines ────────────────────────────────────────────────────────
window.renderMetricsChart = function(deviceID, containerID) {
  fetch(`/metrics/${deviceID}`).then(r => r.json()).then(snaps => {
    if (!snaps || snaps.length < 2) return;
    const el = document.getElementById(containerID);
    if (!el) return;
    const w = el.clientWidth || 200, h = 40;
    const max = Math.max(...snaps.flatMap(s => [s.bytes_sent||0, s.bytes_received||0]), 1);
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', `0 0 ${w} ${h}`);
    svg.style.width = '100%';
    for (const [key, color] of [['bytes_sent','var(--primary)'],['bytes_received','var(--success)']]) {
      const pts = snaps.map((s,i) => `${(i/(snaps.length-1))*w},${h-((s[key]||0)/max)*h}`).join(' ');
      const line = document.createElementNS('http://www.w3.org/2000/svg','polyline');
      line.setAttribute('points', pts);
      line.setAttribute('fill','none');
      line.setAttribute('stroke', color);
      line.setAttribute('stroke-width','1.5');
      svg.appendChild(line);
    }
    el.innerHTML = '';
    el.appendChild(svg);
  }).catch(() => {});
};

// ── Toast ─────────────────────────────────────────────────────────────────────
window.showAdminToast = function(message, type = 'info') {
  const colors = {
    success: { bg: 'var(--success-light)', color: 'var(--success-text)' },
    warning: { bg: 'var(--warning-light)', color: 'var(--warning-text)' },
    error:   { bg: 'var(--error-light)',   color: 'var(--error-text)' },
    info:    { bg: 'var(--primary-light)', color: 'var(--primary)' },
  };
  const c = colors[type] || colors.info;
  const toast = Object.assign(document.createElement('div'), { textContent: message });
  Object.assign(toast.style, {
    position: 'fixed', bottom: '20px', right: '20px', padding: '12px 18px',
    borderRadius: '8px', fontSize: '13px', fontWeight: '500',
    background: c.bg, color: c.color, boxShadow: '0 4px 16px rgba(0,0,0,.15)',
    zIndex: '1000', transition: 'opacity 0.25s',
  });
  document.body.appendChild(toast);
  setTimeout(() => { toast.style.opacity = '0'; setTimeout(() => toast.remove(), 250); }, 3500);
};

function showToast(msg, type) { window.showAdminToast(msg, type); }

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  connectWS();
  document.querySelectorAll('.metrics-chart').forEach(el => {
    if (el.dataset.deviceId) window.renderMetricsChart(el.dataset.deviceId, el.id);
  });
});

// Reconnect WS after HTMX swaps (if somehow lost) and re-init charts
document.body.addEventListener('htmx:afterSwap', () => {
  connectWS();
  document.querySelectorAll('.metrics-chart').forEach(el => {
    if (el.dataset.deviceId) window.renderMetricsChart(el.dataset.deviceId, el.id);
  });
});

})(); // end IIFE