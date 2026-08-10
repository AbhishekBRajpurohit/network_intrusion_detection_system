"""
Flask dashboard for the NIDS project.

Serves the live dashboard UI and JSON API endpoints that the frontend
polls for recent traffic, alerts, and stats. Starts the packet sniffer
in a background thread on launch.

Run with:
    sudo python app.py     (raw sockets need elevated privileges)
"""

from flask import Flask, jsonify, render_template

from utils.logger import init_db, get_recent_traffic, get_recent_alerts, get_stats, get_blocked_ips
from sniffer import start_sniffing_background

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/traffic")
def api_traffic():
    rows = get_recent_traffic(limit=50)
    return jsonify([
        {
            "timestamp": r[0], "src_ip": r[1], "dst_ip": r[2],
            "protocol": r[3], "length": r[4], "label": r[5], "confidence": r[6],
        }
        for r in rows
    ])


@app.route("/api/alerts")
def api_alerts():
    rows = get_recent_alerts(limit=20)
    return jsonify([
        {
            "timestamp": r[0], "src_ip": r[1], "attack_type": r[2],
            "confidence": r[3], "blocked": bool(r[4]),
        }
        for r in rows
    ])


@app.route("/api/stats")
def api_stats():
    return jsonify(get_stats())
@app.route("/api/blocked")
def api_blocked():
    rows = get_blocked_ips()
    return jsonify([
        {
            "src_ip": r[0], "first_blocked": r[1], "last_seen": r[2],
            "alert_count": r[3], "attack_type": r[4],
        }
        for r in rows
    ])

if __name__ == "__main__":
    init_db()
    # Set to your active network interface name (see README for how to find
    # it via `python -c "from scapy.all import conf; print(conf.ifaces)"`).
    # Use iface=None to let scapy pick a default instead.
    start_sniffing_background(iface=None)
    app.run(debug=True, use_reloader=False, host="0.0.0.0", port=5000)