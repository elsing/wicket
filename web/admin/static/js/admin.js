// Wicket admin portal JS

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

// ── Refresh helpers ───────────────────────────────────────────────────────────
// Each function checks which elements exist on the current page and refreshes
// whatever is relevant. The admin may be on dashboard, devices, sessions etc.

function refreshAfterDeviceChange() {
  // Dashboard: refresh entire dashboard content (stats + pending)
  if (document.getElementById('dashboard-content')) {
    htmx.ajax('GET', '/dashboard/fragment', { target: '#dashboard-content', swap: 'innerHTML' });
    return;
  }
  // Devices page: refresh the full table body
  if (document.getElementById('devices-tbody')) {
    htmx.ajax('GET', '/devices', { target: '#devices-tbody', swap: 'innerHTML' });
  }
}

function refreshAfterSessionChange() {
  if (document.getElementById('sessions-table')) {
    htmx.ajax('GET', '/sessions', { target: '#sessions-table', swap: 'innerHTML' });
  }
}

// ── WebSocket ─────────────────────────────────────────────────────────────────
let ws = null;
let wsReconnectTimer = null;

function connectWS() {
  if (wsReconnectTimer) { clearTimeout(wsReconnectTimer); wsReconnectTimer = null; }

  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = `${proto}//${location.host}/ws`;
  console.log('[wicket admin] connecting WS:', url);
  ws = new WebSocket(url);

  ws.onopen = () => {
    console.log('[wicket admin] WS connected');
    document.querySelectorAll('.live-dot').forEach(d => d.style.background = 'var(--success)');
  };

  ws.onmessage = (evt) => {
    try {
      const event = JSON.parse(evt.data);
      console.log('[wicket admin] event:', event.type, event);
      handleEvent(event);
    } catch(e) { console.warn('[wicket admin] bad WS message', evt.data); }
  };

  // Send a ping from client every 25s to keep connection alive through
  // browser tab throttling and proxy idle timeouts.
  let keepaliveInterval = null;

  ws.onopen = (ws.onopen || function(){}).bind(ws);
  const _onopen = ws.onopen;

  ws.addEventListener('open', () => {
    if (keepaliveInterval) clearInterval(keepaliveInterval);
    keepaliveInterval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({type: 'ping'}));
      }
    }, 25000);
  });

  ws.onclose = (e) => {
    console.log('[wicket admin] WS closed', e.code, e.reason, '— reconnecting in 5s');
    document.querySelectorAll('.live-dot').forEach(d => d.style.background = 'var(--error)');
    if (keepaliveInterval) { clearInterval(keepaliveInterval); keepaliveInterval = null; }
    wsReconnectTimer = setTimeout(connectWS, 5000);
  };

  ws.onerror = (e) => {
    console.warn('[wicket admin] WS error', e);
    ws.close();
  };
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
function renderMetricsChart(deviceID, containerID) {
  fetch(`/metrics/${deviceID}`).then(r => r.json()).then(snaps => {
    if (!snaps || snaps.length < 2) return;
    const el = document.getElementById(containerID);
    if (!el) return;
    drawSparkline(el, snaps);
  }).catch(() => {});
}

function drawSparkline(el, snaps) {
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
    position: 'fixed', bottom: '20px', right: '20px', padding: '12px 18px',
    borderRadius: '8px', fontSize: '13px', fontWeight: '500',
    background: c.bg, color: c.color, boxShadow: '0 4px 16px rgba(0,0,0,.15)',
    zIndex: '1000', transition: 'opacity 0.25s',
  });
  document.body.appendChild(toast);
  setTimeout(() => { toast.style.opacity = '0'; setTimeout(() => toast.remove(), 250); }, 3500);
}

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  connectWS();
  document.querySelectorAll('.metrics-chart').forEach(el => {
    if (el.dataset.deviceId) renderMetricsChart(el.dataset.deviceId, el.id);
  });
});