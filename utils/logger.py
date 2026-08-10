"""
SQLite logging for captured traffic and alerts.
Keeps a rolling log so the dashboard can query recent activity.
"""

import sqlite3
import os
import time

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "nids.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            length INTEGER,
            label TEXT,
            confidence REAL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            src_ip TEXT,
            attack_type TEXT,
            confidence REAL,
            blocked INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()


def log_traffic(src_ip, dst_ip, protocol, length, label="normal", confidence=0.0):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO traffic (timestamp, src_ip, dst_ip, protocol, length, label, confidence) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (time.time(), src_ip, dst_ip, protocol, length, label, confidence),
    )
    conn.commit()
    conn.close()


def log_alert(src_ip, attack_type, confidence, blocked=False):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO alerts (timestamp, src_ip, attack_type, confidence, blocked) "
        "VALUES (?, ?, ?, ?, ?)",
        (time.time(), src_ip, attack_type, confidence, int(blocked)),
    )
    conn.commit()
    conn.close()


def get_recent_traffic(limit=50):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT timestamp, src_ip, dst_ip, protocol, length, label, confidence "
        "FROM traffic ORDER BY id DESC LIMIT ?",
        (limit,),
    )
    rows = c.fetchall()
    conn.close()
    return rows


def get_recent_alerts(limit=20):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT timestamp, src_ip, attack_type, confidence, blocked "
        "FROM alerts ORDER BY id DESC LIMIT ?",
        (limit,),
    )
    rows = c.fetchall()
    conn.close()
    return rows


def get_stats():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM traffic")
    total_packets = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM alerts WHERE blocked = 1")
    total_blocked = c.fetchone()[0]
    conn.close()
    return {
        "total_packets": total_packets,
        "total_alerts": total_alerts,
        "total_blocked": total_blocked,
    }

def get_blocked_ips():
    """Returns each currently-blocked IP with when it was first blocked,
    how many times it's been flagged since, and its most common attack type.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT src_ip,
               MIN(timestamp) AS first_blocked,
               MAX(timestamp) AS last_seen,
               COUNT(*) AS alert_count,
               attack_type
        FROM alerts
        WHERE blocked = 1
        GROUP BY src_ip
        ORDER BY last_seen DESC
    """)
    rows = c.fetchall()
    conn.close()
    return rows