const trafficCtx = document.getElementById('trafficChart').getContext('2d');
const trafficChart = new Chart(trafficCtx, {
  type: 'line',
  data: {
    labels: [],
    datasets: [{
      label: 'Packets / poll',
      data: [],
      borderColor: '#5ad1a3',
      backgroundColor: 'rgba(90, 209, 163, 0.15)',
      tension: 0.3,
      fill: true,
    }]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      x: { display: false },
      y: { beginAtZero: true, ticks: { color: '#9aa0ac' } }
    },
    plugins: { legend: { labels: { color: '#e6e6e6' } } }
  }
});

let lastPacketCount = 0;

function fmtTime(ts) {
  return new Date(ts * 1000).toLocaleTimeString();
}

async function refreshStats() {
  const res = await fetch('/api/stats');
  const stats = await res.json();
  document.getElementById('stat-packets').textContent = stats.total_packets;
  document.getElementById('stat-alerts').textContent = stats.total_alerts;
  document.getElementById('stat-blocked').textContent = stats.total_blocked;

  const delta = Math.max(stats.total_packets - lastPacketCount, 0);
  lastPacketCount = stats.total_packets;

  const labels = trafficChart.data.labels;
  const data = trafficChart.data.datasets[0].data;
  labels.push('');
  data.push(delta);
  if (labels.length > 30) { labels.shift(); data.shift(); }
  trafficChart.update();
}

async function refreshAlerts() {
  const res = await fetch('/api/alerts');
  const alerts = await res.json();
  const tbody = document.querySelector('#alerts-table tbody');
  tbody.innerHTML = alerts.map(a => `
    <tr>
      <td>${fmtTime(a.timestamp)}</td>
      <td>${a.src_ip}</td>
      <td class="label-attack">${a.attack_type}</td>
      <td>${(a.confidence * 100).toFixed(0)}%</td>
      <td>${a.blocked ? '✅' : '—'}</td>
    </tr>
  `).join('');
}

async function refreshTraffic() {
  const res = await fetch('/api/traffic');
  const traffic = await res.json();
  const tbody = document.querySelector('#traffic-table tbody');
  tbody.innerHTML = traffic.slice(0, 20).map(t => `
    <tr>
      <td>${fmtTime(t.timestamp)}</td>
      <td>${t.src_ip}</td>
      <td>${t.dst_ip}</td>
      <td>${t.protocol}</td>
      <td class="${t.label === 'normal' ? 'label-normal' : 'label-attack'}">${t.label}</td>
    </tr>
  `).join('');
}

function refreshAll() {
  refreshStats();
  refreshAlerts();
  refreshTraffic();
}

refreshAll();
setInterval(refreshAll, 2000);
