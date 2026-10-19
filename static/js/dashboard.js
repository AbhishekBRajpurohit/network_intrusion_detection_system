// Simple hand-rolled line chart drawn on <canvas> — no external library needed.
const trafficCanvas = document.getElementById('trafficChart');
const trafficCtx = trafficCanvas.getContext('2d');
const trafficData = []; // rolling window of packet-delta values
const MAX_POINTS = 30;

function resizeCanvas() {
  const rect = trafficCanvas.parentElement.getBoundingClientRect();
  trafficCanvas.width = rect.width;
  trafficCanvas.height = rect.height;
}

function drawTrafficChart() {
  const w = trafficCanvas.width;
  const h = trafficCanvas.height;
  trafficCtx.clearRect(0, 0, w, h);

  if (trafficData.length < 2) return;

  const maxVal = Math.max(...trafficData, 1);
  const padding = 10;
  const stepX = (w - padding * 2) / (MAX_POINTS - 1);

  const toX = (i) => padding + i * stepX;
  const toY = (v) => h - padding - (v / maxVal) * (h - padding * 2);

  trafficCtx.beginPath();
  trafficCtx.moveTo(toX(0), h - padding);
  trafficData.forEach((v, i) => trafficCtx.lineTo(toX(i), toY(v)));
  trafficCtx.lineTo(toX(trafficData.length - 1), h - padding);
  trafficCtx.closePath();
  trafficCtx.fillStyle = 'rgba(90, 209, 163, 0.15)';
  trafficCtx.fill();

  trafficCtx.beginPath();
  trafficData.forEach((v, i) => {
    const x = toX(i), y = toY(v);
    if (i === 0) trafficCtx.moveTo(x, y);
    else trafficCtx.lineTo(x, y);
  });
  trafficCtx.strokeStyle = '#5ad1a3';
  trafficCtx.lineWidth = 2;
  trafficCtx.stroke();
}

window.addEventListener('resize', () => { resizeCanvas(); drawTrafficChart(); });
resizeCanvas();

let lastPacketCount = 0;

function getCsrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  if (meta && meta.content) return meta.content;
  const input = document.querySelector('input[name="csrf"]');
  return input ? input.value : '';
}

function fmtTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' ' + d.toLocaleDateString();
}

function escapeHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// State for pagination, filters, and alert cache
let alertsPage = 1;
const alertsLimit = 15;
let alertsTotal = 0;
const alertsCache = new Map();

let trafficPage = 1;
const trafficLimit = 15;
let trafficTotal = 0;

const currentFilters = {
  ip: '',
  start_date: '',
  end_date: '',
  status: ''
};

function buildQueryParams(page, limit) {
  const params = new URLSearchParams();
  params.set('page', page);
  params.set('limit', limit);
  if (currentFilters.ip) params.set('ip', currentFilters.ip);
  if (currentFilters.start_date) params.set('start_date', currentFilters.start_date);
  if (currentFilters.end_date) params.set('end_date', currentFilters.end_date);
  if (currentFilters.status) params.set('status', currentFilters.status);
  return params.toString();
}

let lastSuccessfulSync = null;
let consecutiveErrors = 0;
let isSyncing = false;

function setConnectionState(ok, errorMsg = '') {
  const banner = document.getElementById('connection-banner');
  const bannerMsg = document.getElementById('banner-message');
  const syncDot = document.getElementById('sync-dot');
  const syncLabel = document.getElementById('sync-label');

  if (ok) {
    consecutiveErrors = 0;
    lastSuccessfulSync = Date.now();
    if (banner) banner.style.display = 'none';
    if (syncDot) syncDot.className = 'sync-dot live';
    if (syncLabel) syncLabel.textContent = 'Connected';
    updateSyncTime();
  } else {
    consecutiveErrors++;
    if (banner) {
      banner.style.display = 'flex';
      if (bannerMsg) {
        bannerMsg.textContent = errorMsg || 'Unable to reach the NIDS backend server. Displaying cached data.';
      }
    }
    if (syncDot) syncDot.className = 'sync-dot error';
    if (syncLabel) syncLabel.textContent = 'Disconnected';
  }
}

function updateSyncTime() {
  const syncTimeEl = document.getElementById('sync-time');
  if (!syncTimeEl) return;
  if (!lastSuccessfulSync) {
    syncTimeEl.textContent = '—';
    return;
  }
  const secAgo = Math.floor((Date.now() - lastSuccessfulSync) / 1000);
  if (secAgo < 3) {
    syncTimeEl.textContent = '• synced just now';
  } else if (secAgo < 60) {
    syncTimeEl.textContent = `• synced ${secAgo}s ago`;
  } else {
    syncTimeEl.textContent = `• synced ${Math.floor(secAgo / 60)}m ago`;
  }
}

setInterval(updateSyncTime, 1000);

async function refreshStats() {
  const params = new URLSearchParams();
  if (currentFilters.ip) params.set('ip', currentFilters.ip);
  if (currentFilters.start_date) params.set('start_date', currentFilters.start_date);
  if (currentFilters.end_date) params.set('end_date', currentFilters.end_date);
  const qs = params.toString() ? '?' + params.toString() : '';

  const res = await fetch('/api/stats' + qs);
  if (res.status === 401) { window.location.href = '/login'; return; }
  if (!res.ok) throw new Error(`Stats endpoint returned HTTP ${res.status}`);
  const stats = await res.json();
  document.getElementById('stat-packets').textContent = stats.total_packets ?? stats.traffic ?? 0;
  document.getElementById('stat-alerts').textContent = stats.total_alerts ?? stats.alerts ?? 0;
  document.getElementById('stat-blocked').textContent = stats.active_blocks ?? 0;
  document.getElementById('stat-blocked-total').textContent = `${stats.total_blocked ?? 0} historical`;

  const currentTotal = stats.total_packets ?? stats.traffic ?? 0;
  const delta = Math.max(currentTotal - lastPacketCount, 0);
  lastPacketCount = currentTotal;

  trafficData.push(delta);
  if (trafficData.length > MAX_POINTS) trafficData.shift();
  drawTrafficChart();
}

async function refreshAlerts() {
  const qs = buildQueryParams(alertsPage, alertsLimit);
  const res = await fetch('/api/alerts?' + qs);
  if (res.status === 401) { window.location.href = '/login'; return; }
  if (!res.ok) throw new Error(`Alerts endpoint returned HTTP ${res.status}`);
  const data = await res.json();
  const rows = Array.isArray(data) ? data : (data.rows || []);
  alertsTotal = data.total ?? rows.length;

  // Cache rows for quick modal access
  rows.forEach(r => { if (r.id) alertsCache.set(Number(r.id), r); });

  const tbody = document.querySelector('#alerts-table tbody');
  if (rows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: #9aa0ac; padding: 18px;">No alerts match the selected criteria</td></tr>';
  } else {
    tbody.innerHTML = rows.map(a => {
      const status = a.status || 'New';
      const statusClass = `status-${status.toLowerCase()}`;
      const isRule = (a.source || '').toLowerCase() === 'rule';
      const confDisplay = isRule
        ? '<span class="badge-source badge-rule" title="Deterministic Rule Match">Rule Match</span>'
        : (a.confidence != null
            ? `<span class="badge-source badge-ml" title="Machine Learning Probability">${(a.confidence * 100).toFixed(0)}% (ML)</span>`
            : '—');
      return `
        <tr data-alert-id="${a.id}">
          <td>${fmtTime(a.timestamp)}</td>
          <td><strong>${escapeHtml(a.src_ip || '—')}</strong></td>
          <td class="label-attack">${escapeHtml(a.attack_type || 'unknown')}</td>
          <td>${confDisplay}</td>
          <td>
            <select class="status-dropdown ${statusClass}" data-alert-id="${a.id}" aria-label="Alert Status">
              <option value="New" ${status === 'New' ? 'selected' : ''}>New</option>
              <option value="Investigating" ${status === 'Investigating' ? 'selected' : ''}>Investigating</option>
              <option value="Resolved" ${status === 'Resolved' ? 'selected' : ''}>Resolved</option>
            </select>
          </td>
          <td>
            <button type="button" class="btn-details" data-alert-id="${a.id}">🔍 Details</button>
          </td>
        </tr>
      `;
    }).join('');
  }

  // Update pagination controls
  const totalPages = Math.max(1, Math.ceil(alertsTotal / alertsLimit));
  document.getElementById('alerts-page-info').textContent =
    alertsTotal > 0
      ? `Showing ${(alertsPage - 1) * alertsLimit + 1}–${Math.min(alertsPage * alertsLimit, alertsTotal)} of ${alertsTotal}`
      : '0 records';
  document.getElementById('alerts-current-page').textContent = `Page ${alertsPage} of ${totalPages}`;
  document.getElementById('alerts-prev').disabled = alertsPage <= 1;
  document.getElementById('alerts-next').disabled = alertsPage >= totalPages;
}

async function refreshTraffic() {
  const qs = buildQueryParams(trafficPage, trafficLimit);
  const res = await fetch('/api/traffic?' + qs);
  if (res.status === 401) { window.location.href = '/login'; return; }
  if (!res.ok) throw new Error(`Traffic endpoint returned HTTP ${res.status}`);
  const data = await res.json();
  const rows = Array.isArray(data) ? data : (data.rows || []);
  trafficTotal = data.total ?? rows.length;

  const tbody = document.querySelector('#traffic-table tbody');
  if (rows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #9aa0ac; padding: 18px;">No traffic records match the filters</td></tr>';
  } else {
    tbody.innerHTML = rows.map(t => `
      <tr>
        <td>${fmtTime(t.timestamp)}</td>
        <td>${escapeHtml(t.src_ip || '—')}</td>
        <td>${escapeHtml(t.dst_ip || '—')}</td>
        <td>${escapeHtml(t.protocol || '—')}</td>
        <td class="${t.label === 'normal' ? 'label-normal' : 'label-attack'}">${escapeHtml(t.label || 'normal')}</td>
      </tr>
    `).join('');
  }

  const totalPages = Math.max(1, Math.ceil(trafficTotal / trafficLimit));
  document.getElementById('traffic-page-info').textContent =
    trafficTotal > 0
      ? `Showing ${(trafficPage - 1) * trafficLimit + 1}–${Math.min(trafficPage * trafficLimit, trafficTotal)} of ${trafficTotal}`
      : '0 records';
  document.getElementById('traffic-current-page').textContent = `Page ${trafficPage} of ${totalPages}`;
  document.getElementById('traffic-prev').disabled = trafficPage <= 1;
  document.getElementById('traffic-next').disabled = trafficPage >= totalPages;
}

async function refreshStatus() {
  const res = await fetch('/api/status');
  if (res.status === 401) return;
  if (!res.ok) throw new Error(`Status endpoint returned HTTP ${res.status}`);
  const data = await res.json();
  const capture = data.capture || {};
  const state = capture.state || data.status || 'unknown';

  const dot = document.getElementById('capture-dot');
  const label = document.getElementById('capture-label');

  const colors = { running: '#5ad1a3', stopped: '#888', error: '#e85d75', unknown: '#f0a500' };
  if (dot) dot.style.background = colors[state] || colors.unknown;

  let text = state.charAt(0).toUpperCase() + state.slice(1);
  if (state === 'running' && capture.interface) {
    text += ` (${capture.interface})`;
  }
  if (state === 'error' && capture.error) {
    text += `: ${capture.error}`;
  }
  if (label) label.textContent = text;
}

async function setAlertStatus(alertId, newStatus) {
  try {
    const res = await fetch(`/api/alerts/${alertId}/status`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCsrfToken()
      },
      body: JSON.stringify({ status: newStatus })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      alert('Could not update alert status: ' + (err.error || res.statusText));
      return false;
    }
    // Update cached alert
    const cached = alertsCache.get(Number(alertId));
    if (cached) cached.status = newStatus;

    // Update table dropdown styling
    const select = document.querySelector(`select[data-alert-id="${alertId}"]`);
    if (select) {
      select.value = newStatus;
      select.className = `status-dropdown status-${newStatus.toLowerCase()}`;
    }
    return true;
  } catch (err) {
    console.error('Error updating alert status:', err);
    alert('Network error updating status');
    return false;
  }
}

let activeModalAlertId = null;

function showModal(alertData) {
  if (!alertData) return;
  activeModalAlertId = alertData.id;

  document.getElementById('modal-title').textContent = `${alertData.attack_type || 'Alert'} (#${alertData.id})`;
  document.getElementById('modal-reason').textContent = alertData.reason || 'Flagged by detection rule / machine learning threshold.';

  // Feature metrics
  const feats = alertData.features || {};
  document.getElementById('m-packet-rate').textContent =
    feats.packet_rate != null ? Number(feats.packet_rate).toFixed(1) : '—';
  document.getElementById('m-unique-ports').textContent =
    feats.unique_ports != null ? feats.unique_ports : '—';
  document.getElementById('m-syn-rate').textContent =
    feats.syn_rate != null ? Number(feats.syn_rate).toFixed(1) : '—';
  document.getElementById('m-avg-len').textContent =
    feats.avg_packet_len != null ? Math.round(feats.avg_packet_len) : '—';

  // Metadata
  const isRule = (alertData.source || '').toLowerCase() === 'rule';
  document.getElementById('m-id').textContent = alertData.id || '—';
  document.getElementById('m-src-ip').textContent = alertData.src_ip || '—';
  document.getElementById('m-source').textContent = isRule ? 'RULE (Deterministic)' : 'MACHINE LEARNING';
  document.getElementById('m-severity').textContent = (alertData.severity || 'high').toUpperCase();
  document.getElementById('m-confidence').textContent = isRule
    ? 'Rule Match (Deterministic threshold, not probabilistic)'
    : (alertData.confidence != null ? (alertData.confidence * 100).toFixed(1) + '% (ML probability)' : '—');
  document.getElementById('m-blocked').textContent = alertData.blocked ? 'Yes (Firewall Block Rule Added)' : 'No (Alert Only)';
  document.getElementById('m-time').textContent = fmtTime(alertData.timestamp);

  const statusSel = document.getElementById('modal-status-select');
  statusSel.value = alertData.status || 'New';

  document.getElementById('alert-modal').style.display = 'flex';
}

function closeModal() {
  document.getElementById('alert-modal').style.display = 'none';
  activeModalAlertId = null;
}

// Event Listeners Initialization
function initEventListeners() {
  // Filter apply & reset
  const btnApply = document.getElementById('btn-apply-filters');
  if (btnApply) {
    btnApply.addEventListener('click', () => {
      currentFilters.ip = document.getElementById('filter-ip').value.trim();
      currentFilters.start_date = document.getElementById('filter-start-date').value;
      currentFilters.end_date = document.getElementById('filter-end-date').value;
      currentFilters.status = document.getElementById('filter-status').value;
      alertsPage = 1;
      trafficPage = 1;
      refreshAlerts();
      refreshTraffic();
      refreshStats();
    });
  }

  const btnReset = document.getElementById('btn-reset-filters');
  if (btnReset) {
    btnReset.addEventListener('click', () => {
      document.getElementById('filter-ip').value = '';
      document.getElementById('filter-start-date').value = '';
      document.getElementById('filter-end-date').value = '';
      document.getElementById('filter-status').value = '';
      currentFilters.ip = '';
      currentFilters.start_date = '';
      currentFilters.end_date = '';
      currentFilters.status = '';
      alertsPage = 1;
      trafficPage = 1;
      refreshAlerts();
      refreshTraffic();
      refreshStats();
    });
  }

  // Enter key on IP input
  const ipInput = document.getElementById('filter-ip');
  if (ipInput) {
    ipInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        btnApply.click();
      }
    });
  }

  // Alerts table event delegation for Details button & Status dropdown
  const alertsTable = document.getElementById('alerts-table');
  if (alertsTable) {
    alertsTable.addEventListener('click', async (e) => {
      const btn = e.target.closest('.btn-details');
      if (btn) {
        const id = Number(btn.getAttribute('data-alert-id'));
        let alertData = alertsCache.get(id);
        if (!alertData) {
          try {
            const res = await fetch(`/api/alerts/${id}`);
            if (res.ok) alertData = await res.json();
          } catch (err) {
            console.error('Failed to load alert detail:', err);
          }
        }
        if (alertData) showModal(alertData);
      }
    });

    alertsTable.addEventListener('change', async (e) => {
      if (e.target.classList.contains('status-dropdown')) {
        const id = Number(e.target.getAttribute('data-alert-id'));
        const newStatus = e.target.value;
        await setAlertStatus(id, newStatus);
      }
    });
  }

  // Modal Status change
  const modalStatusSelect = document.getElementById('modal-status-select');
  if (modalStatusSelect) {
    modalStatusSelect.addEventListener('change', async () => {
      if (activeModalAlertId) {
        await setAlertStatus(activeModalAlertId, modalStatusSelect.value);
      }
    });
  }

  // Modal Close buttons & backdrop click
  const modalClose = document.getElementById('modal-close');
  if (modalClose) modalClose.addEventListener('click', closeModal);
  const modalBtnClose = document.getElementById('modal-btn-close');
  if (modalBtnClose) modalBtnClose.addEventListener('click', closeModal);

  const modal = document.getElementById('alert-modal');
  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) closeModal();
    });
  }

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && modal && modal.style.display !== 'none') {
      closeModal();
    }
  });

  // Pagination buttons
  document.getElementById('alerts-prev')?.addEventListener('click', () => {
    if (alertsPage > 1) { alertsPage--; refreshAlerts(); }
  });
  document.getElementById('alerts-next')?.addEventListener('click', () => {
    alertsPage++; refreshAlerts();
  });

  document.getElementById('traffic-prev')?.addEventListener('click', () => {
    if (trafficPage > 1) { trafficPage--; refreshTraffic(); }
  });
  document.getElementById('traffic-next')?.addEventListener('click', () => {
    trafficPage++; refreshTraffic();
  });

  // Reconnect retry button
  document.getElementById('btn-reconnect')?.addEventListener('click', () => {
    refreshAll();
  });
}

async function refreshAll() {
  if (isSyncing) return;
  isSyncing = true;
  const syncDot = document.getElementById('sync-dot');
  if (consecutiveErrors === 0 && syncDot) {
    syncDot.className = 'sync-dot syncing';
  }

  try {
    const results = await Promise.allSettled([
      refreshStats(),
      refreshAlerts(),
      refreshTraffic(),
      refreshStatus()
    ]);
    const anyFailed = results.some(r => r.status === 'rejected');
    if (anyFailed) {
      const firstError = results.find(r => r.status === 'rejected')?.reason;
      console.warn('Dashboard sync issue:', firstError);
      setConnectionState(false, 'Unable to reach the NIDS backend server. Displaying cached data.');
    } else {
      setConnectionState(true);
    }
  } catch (err) {
    console.error('Error refreshing dashboard:', err);
    setConnectionState(false, 'Connection error: Unable to contact server.');
  } finally {
    isSyncing = false;
  }
}

initEventListeners();
refreshAll();
setInterval(refreshAll, 3000);