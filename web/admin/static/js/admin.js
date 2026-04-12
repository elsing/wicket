// ── Confirmation Modal ────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', function() {
  const modal = document.createElement('div');
  modal.id = 'confirm-modal';
  modal.style.cssText = 'display:none;position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.45);align-items:center;justify-content:center';
  modal.innerHTML = `
    <div style="background:var(--bg-1,#fff);border-radius:10px;padding:24px 28px;max-width:400px;width:90%;box-shadow:0 8px 32px rgba(0,0,0,.18)">
      <p id="confirm-modal-msg" style="margin:0 0 20px;font-size:15px;color:var(--text-1)"></p>
      <div style="display:flex;gap:10px;justify-content:flex-end">
        <button id="confirm-modal-cancel" class="btn btn-ghost">Cancel</button>
        <button id="confirm-modal-ok" class="btn" style="background:var(--error-bg,#fee2e2);color:var(--error-text,#b91c1c);border:1px solid var(--error-text,#b91c1c)">Confirm</button>
      </div>
    </div>`;
  document.body.appendChild(modal);

  let resolveFn = null;

  function showModal(msg) {
    return new Promise(resolve => {
      resolveFn = resolve;
      document.getElementById('confirm-modal-msg').textContent = msg;
      modal.style.display = 'flex';
    });
  }

  function hideModal(result) {
    modal.style.display = 'none';
    if (resolveFn) { resolveFn(result); resolveFn = null; }
  }

  document.getElementById('confirm-modal-cancel').addEventListener('click', () => hideModal(false));
  document.getElementById('confirm-modal-ok').addEventListener('click', () => hideModal(true));
  modal.addEventListener('click', e => { if (e.target === modal) hideModal(false); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') hideModal(false); });

  // Intercept htmx confirm events
  document.body.addEventListener('htmx:confirm', function(e) {
    if (!e.detail.question) return;
    e.preventDefault();
    showModal(e.detail.question).then(ok => {
      if (ok) e.detail.issueRequest(true);
    });
  });
});

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
    // Use htmx.ajax so HTMX processes the new content and wires up hx-* attributes
    htmx.ajax('GET', '/devices', { target: '#devices-tbody', swap: 'innerHTML' });
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
      setTimeout(refreshMetrics, 2000); // give WG time to report first stats
      break;
    case 'peer.removed':
      showToast('WireGuard peer removed', 'info');
      setTimeout(refreshMetrics, 1000);
      break;
  }
}

// ── Metrics sparklines ────────────────────────────────────────────────────────
window.renderMetricsChart = function(deviceID, containerID) {
  fetch(`/metrics/${deviceID}`).then(r => r.json()).then(points => {
    if (!points || points.length < 2) {
      const el = document.getElementById(containerID);
      if (el) el.innerHTML = '<span style="font-size:11px;color:var(--text-3)">No data</span>';
      return;
    }
    const el = document.getElementById(containerID);
    if (!el) return;
    const w = el.clientWidth || 200, h = 40;
    const max = Math.max(...points.flatMap(p => [p.bytes_sent||0, p.bytes_received||0]), 1);
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', `0 0 ${w} ${h}`);
    svg.style.width = '100%';
    svg.style.overflow = 'visible';

    // Draw filled areas for visual impact
    for (const [key, color] of [['bytes_sent','var(--primary)'],['bytes_received','var(--success)']]) {
      if (points.length < 2) continue;
      const pts = points.map((p,i) => {
        const x = (i/(points.length-1))*w;
        const y = h - ((p[key]||0)/max)*(h-2);
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      });
      // Area fill
      const area = document.createElementNS('http://www.w3.org/2000/svg','polyline');
      area.setAttribute('points', [`0,${h}`, ...pts, `${w},${h}`].join(' '));
      area.setAttribute('fill', color);
      area.setAttribute('fill-opacity', '0.15');
      area.setAttribute('stroke', 'none');
      svg.appendChild(area);
      // Line
      const line = document.createElementNS('http://www.w3.org/2000/svg','polyline');
      line.setAttribute('points', pts.join(' '));
      line.setAttribute('fill','none');
      line.setAttribute('stroke', color);
      line.setAttribute('stroke-width','1.5');
      svg.appendChild(line);
    }

    // Legend
    const legend = document.createElementNS('http://www.w3.org/2000/svg','text');
    legend.setAttribute('x', '2');
    legend.setAttribute('y', '10');
    legend.setAttribute('font-size', '9');
    legend.setAttribute('fill', 'var(--text-3)');
    legend.textContent = `↑ ${fmtRate(Math.max(...points.map(p=>p.bytes_sent||0)))} ↓ ${fmtRate(Math.max(...points.map(p=>p.bytes_received||0)))} peak`;
    svg.appendChild(legend);

    el.innerHTML = '';
    el.appendChild(svg);
  }).catch(() => {});
};

function fmtRate(bps) {
  if (bps < 1024) return `${bps.toFixed(0)}B/s`;
  if (bps < 1024*1024) return `${(bps/1024).toFixed(1)}K/s`;
  return `${(bps/1024/1024).toFixed(1)}M/s`;
}

// ── Group edit toggle ─────────────────────────────────────────────────────────
// Refresh agents list when a new agent is created
document.body.addEventListener('refreshAgentsList', function() {
  htmx.ajax('GET', '/agents/list', {target: '#agents-content', swap: 'innerHTML'});
});

// Reset create group form after successful submission
document.body.addEventListener('resetGroupForm', function() {
  const form = document.querySelector('form[hx-post="/groups"]');
  if (form) {
    form.reset();
    const errDiv = document.getElementById('group-form-error');
    if (errDiv) errDiv.innerHTML = '';
  }
});

// Event delegation for data-attribute based toggles (templ-safe approach)
document.addEventListener('click', function(e) {
  const groupEl = e.target.closest('[data-toggle-group-edit]');
  if (groupEl) { window.toggleGroupEdit(groupEl.dataset.toggleGroupEdit); return; }
  const agentEl = e.target.closest('[data-toggle-agent-edit]');
  if (agentEl) { window.toggleAgentEdit(agentEl.dataset.toggleAgentEdit); return; }
});

window.toggleAgentEdit = function(agentID) {
  const el = document.getElementById('agent-edit-' + agentID);
  if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
};

window.toggleGroupEdit = function(groupID) {
  const el = document.getElementById('edit-' + groupID);
  if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
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

function initCharts() {
  document.querySelectorAll('.metrics-chart').forEach(el => {
    if (el.dataset.deviceId) window.renderMetricsChart(el.dataset.deviceId, el.id);
  });
}

function refreshMetrics() {
  if (!document.getElementById('metrics-content')) return;
  fetch('/metrics/fragment', { headers: { 'HX-Request': 'true' } })
    .then(r => r.text())
    .then(html => {
      const el = document.getElementById('metrics-content');
      if (el) {
        el.innerHTML = html;
        initCharts();
      }
    })
    .catch(() => {});
}

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  connectWS();
  initCharts();

  // Auto-refresh metrics every 30s when on that page
  if (document.getElementById('metrics-content')) {
    if (window._metricsInterval) clearInterval(window._metricsInterval);
    window._metricsInterval = setInterval(refreshMetrics, 30000);
  }
});

document.body.addEventListener('htmx:afterSwap', () => {
  connectWS();
  initCharts();
  // Start/stop metrics polling based on whether we are on the metrics page
  if (document.getElementById('metrics-content')) {
    if (!window._metricsInterval)
      window._metricsInterval = setInterval(refreshMetrics, 30000);
  } else {
    if (window._metricsInterval) {
      clearInterval(window._metricsInterval);
      window._metricsInterval = null;
    }
  }
});

})(); // end IIFE