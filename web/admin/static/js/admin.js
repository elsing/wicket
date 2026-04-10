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
function refreshPending() {
  if (document.getElementById('pending-devices'))
    htmx.ajax('GET', '/devices/pending', { target: '#pending-devices', swap: 'innerHTML' });
}

function refreshDevicesTable() {
  if (document.getElementById('devices-tbody'))
    htmx.ajax('GET', '/devices', { target: '#devices-tbody', swap: 'innerHTML' });
}

function refreshSessions() {
  if (document.getElementById('sessions-table'))
    htmx.ajax('GET', '/sessions', { target: '#sessions-table', swap: 'innerHTML' });
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
    try { handleEvent(JSON.parse(evt.data)); } catch(e) {}
  };

  ws.onclose = () => {
    const dot = document.querySelector('.live-dot');
    if (dot) dot.style.background = 'var(--error)';
    console.log('[wicket admin] WS disconnected, reconnecting...');
    setTimeout(connectWS, 5000);
  };

  ws.onerror = () => ws.close();
}

function handleEvent(event) {
  console.log('[wicket admin]', event.type, event);
  switch (event.type) {
    case 'device.created':
      refreshPending();
      refreshDevicesTable();
      showToast('New device pending approval', 'warning');
      break;
    case 'device.approved':
      refreshPending();
      refreshDevicesTable();
      showToast('Device approved', 'success');
      break;
    case 'device.rejected':
      refreshPending();
      refreshDevicesTable();
      break;
    case 'session.created':
      refreshSessions();
      showToast('Session activated', 'success');
      break;
    case 'session.revoked':
    case 'session.expired':
      refreshSessions();
      break;
    case 'peer.added':
      showToast('WireGuard peer added', 'success');
      break;
    case 'peer.removed':
      showToast('WireGuard peer removed', 'info');
      refreshDevicesTable();
      break;
  }
}

// ── Metrics sparklines ────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  connectWS();
  document.querySelectorAll('.metrics-chart').forEach(el => {
    const id = el.dataset.deviceId;
    if (id) renderMetricsChart(id, el.id);
  });
});

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