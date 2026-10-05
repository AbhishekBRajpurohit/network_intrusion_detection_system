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

function fmtTime(ts) {
  return new Date(ts * 1000).toLocaleTimeString();
}

async function refreshStats() {
  try {
    const res = await fetch('/api/stats');
    if (res.status === 401) { window.location.href = '/login'; return; }
    const stats = await res.json();
    document.getElementById('stat-packets').textContent = stats.total_packets ?? stats.traffic ?? 0;
    document.getElementById('stat-alerts').textContent = stats.total_alerts ?? stats.alerts ?? 0;
    document.getElementById('stat-blocked').textContent = stats.total_blocked ?? 0;

    const currentTotal = stats.total_packets ?? stats.traffic ?? 0;
    const delta = Math.max(currentTotal - lastPacketCount, 0);
    lastPacketCount = currentTotal;

    trafficData.push(delta);
    if (trafficData.length > MAX_POINTS) trafficData.shift();
    drawTrafficChart();
  } catch (err) {
    console.error('Error fetching stats:', err);
  }
}

async function refreshAlerts() {
  try {
    const res = await fetch('/api/alerts');
    if (res.status === 401) return;
    const data = await res.json();
    const alerts = Array.isArray(data) ? data : (data.rows || []);
    const tbody = document.querySelector('#alerts-table tbody');
    tbody.innerHTML = alerts.map(a => `
      <tr>
        <td>${fmtTime(a.timestamp)}</td>
        <td>${a.src_ip || '—'}</td>
        <td class="label-attack">${a.attack_type || 'unknown'}</td>
        <td>${a.confidence != null ? (a.confidence * 100).toFixed(0) + '%' : '—'}</td>
        <td>${a.blocked ? '✅' : '—'}</td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Error fetching alerts:', err);
  }
}

async function refreshTraffic() {
  try {
    const res = await fetch('/api/traffic');
    if (res.status === 401) return;
    const data = await res.json();
    const traffic = Array.isArray(data) ? data : (data.rows || []);
    const tbody = document.querySelector('#traffic-table tbody');
    tbody.innerHTML = traffic.slice(0, 20).map(t => `
      <tr>
        <td>${fmtTime(t.timestamp)}</td>
        <td>${t.src_ip || '—'}</td>
        <td>${t.dst_ip || '—'}</td>
        <td>${t.protocol || '—'}</td>
        <td class="${t.label === 'normal' ? 'label-normal' : 'label-attack'}">${t.label || 'normal'}</td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Error fetching traffic:', err);
  }
}

function refreshAll() {
  refreshStats();
  refreshAlerts();
  refreshTraffic();
}

refreshAll();
setInterval(refreshAll, 2000);