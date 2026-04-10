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

// ── WebSocket ─────────────────────────────────────────────────────────────────
let ws = null;

function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${proto}//${location.host}/ws`);

  ws.onopen = () => {
    console.log('[wicket admin] WS connected');
    const dot = document.querySelector('.live-dot');
    if (dot) dot.style.background = 'var(--success)';
  };

  ws.onmessage = (evt) => {
    try {
      const event = JSON.parse(evt.data);
      handleAdminEvent(event);
    } catch (e) { /* not JSON */ }
  };

  ws.onclose = () => {
    const dot = document.querySelector('.live-dot');
    if (dot) dot.style.background = 'var(--error)';
    setTimeout(connectWS, 5000);
  };

  ws.onerror = () => ws.close();
}

function handleAdminEvent(event) {
  console.log('[wicket admin] event:', event.type);

  switch (event.type) {
    case 'device.created':
      refreshPending();
      showToast('New device pending approval', 'warning');
      break;
    case 'device.approved':
    case 'device.rejected':
      refreshPending();
      break;
    case 'session.created':
    case 'session.revoked':
    case 'session.expired':
      refreshSessions();
      break;
    case 'peer.added':
      showToast('Peer added to WireGuard', 'success');
      break;
    case 'peer.removed':
      showToast('Peer removed from WireGuard', 'info');
      break;
  }
}

function refreshPending() {
  const el = document.getElementById('pending-devices');
  if (el) htmx.ajax('GET', '/devices/pending', { target: '#pending-devices', swap: 'innerHTML' });
}

function refreshSessions() {
  const el = document.getElementById('sessions-table');
  if (el) htmx.ajax('GET', '/sessions', { target: '#sessions-table', swap: 'innerHTML', select: 'tbody' });
}

// ── Metrics charts ────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  connectWS();
  document.querySelectorAll('.metrics-chart').forEach(el => {
    const deviceID = el.dataset.deviceId;
    if (deviceID) renderMetricsChart(deviceID, el.id);
  });
});

function renderMetricsChart(deviceID, containerID) {
  fetch(`/metrics/${deviceID}`)
    .then(r => r.json())
    .then(snaps => {
      if (!snaps || snaps.length === 0) return;
      const container = document.getElementById(containerID);
      if (!container) return;
      drawSparkline(container, snaps);
    })
    .catch(() => {});
}

function drawSparkline(container, snaps) {
  const w = container.clientWidth || 200;
  const h = 40;
  const maxVal = Math.max(...snaps.map(s => Math.max(s.bytes_sent || 0, s.bytes_received || 0)), 1);
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', `0 0 ${w} ${h}`);
  svg.style.width = '100%';
  [
    { key: 'bytes_sent', color: 'var(--primary)' },
    { key: 'bytes_received', color: 'var(--success)' },
  ].forEach(({ key, color }) => {
    if (snaps.length < 2) return;
    const pts = snaps.map((s, i) => {
      const x = (i / (snaps.length - 1)) * w;
      const y = h - ((s[key] || 0) / maxVal) * h;
      return `${x},${y}`;
    }).join(' ');
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'polyline');
    line.setAttribute('points', pts);
    line.setAttribute('fill', 'none');
    line.setAttribute('stroke', color);
    line.setAttribute('stroke-width', '1.5');
    svg.appendChild(line);
  });
  container.innerHTML = '';
  container.appendChild(svg);
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
    position: 'fixed', bottom: '20px', right: '20px',
    padding: '12px 18px', borderRadius: '8px',
    fontSize: '13px', fontWeight: '500',
    background: c.bg, color: c.color,
    boxShadow: '0 4px 16px rgba(0,0,0,.15)',
    zIndex: '1000',
  });
  document.body.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.25s';
    setTimeout(() => toast.remove(), 250);
  }, 3500);
}