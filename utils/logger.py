"""SQLite logging and queries for captured traffic, alerts, users, and audit records."""

import sqlite3
import os
import time
import json
import contextlib

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "nids.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            length INTEGER,
            label TEXT,
            confidence REAL,
            source TEXT,
            severity TEXT,
            reason TEXT,
            features TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            src_ip TEXT,
            attack_type TEXT,
            confidence REAL,
            blocked INTEGER DEFAULT 0,
            source TEXT,
            severity TEXT,
            reason TEXT,
            features TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            action TEXT,
            ip TEXT,
            success INTEGER,
            detail TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS capture_status (
            id INTEGER PRIMARY KEY,
            state TEXT NOT NULL,
            interface TEXT,
            error TEXT,
            started_at REAL,
            updated_at REAL,
            pid INTEGER
        )
    """)

    # Migrate existing tables if they lack new columns
    existing_traffic_cols = {r[1] for r in c.execute("PRAGMA table_info(traffic)")}
    for col in ("source", "severity", "reason", "features"):
        if col not in existing_traffic_cols:
            c.execute(f"ALTER TABLE traffic ADD COLUMN {col} TEXT")

    existing_alert_cols = {r[1] for r in c.execute("PRAGMA table_info(alerts)")}
    for col in ("source", "severity", "reason", "features"):
        if col not in existing_alert_cols:
            c.execute(f"ALTER TABLE alerts ADD COLUMN {col} TEXT")

    conn.commit()
    conn.close()


def _ensure_capture_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS capture_status (
            id INTEGER PRIMARY KEY,
            state TEXT NOT NULL,
            interface TEXT,
            error TEXT,
            started_at REAL,
            updated_at REAL,
            pid INTEGER
        )
    """)


def update_capture_status(state, interface=None, error=None, started_at=None):
    now = time.time()
    pid = os.getpid()
    with connect() as conn:
        _ensure_capture_table(conn)
        row = conn.execute("SELECT id, started_at FROM capture_status WHERE id = 1").fetchone()
        if row:
            st = started_at if started_at is not None else row["started_at"]
            conn.execute(
                "UPDATE capture_status SET state = ?, interface = ?, error = ?, started_at = ?, updated_at = ?, pid = ? WHERE id = 1",
                (state, interface, error, st, now, pid),
            )
        else:
            conn.execute(
                "INSERT INTO capture_status (id, state, interface, error, started_at, updated_at, pid) VALUES (1, ?, ?, ?, ?, ?, ?)",
                (state, interface, error, started_at or now, now, pid),
            )


def read_capture_status(heartbeat_timeout=8.0):
    try:
        with connect() as conn:
            _ensure_capture_table(conn)
            row = conn.execute("SELECT * FROM capture_status WHERE id = 1").fetchone()
            if not row:
                return {"state": "stopped", "interface": None}
            data = dict(row)
            state = data["state"]
            now = time.time()
            if state == "running":
                if now - (data["updated_at"] or 0) > heartbeat_timeout:
                    return {"state": "stopped", "interface": None}
                uptime = round(now - (data["started_at"] or now), 1)
                return {
                    "state": "running",
                    "interface": data["interface"],
                    "uptime_seconds": uptime,
                }
            elif state == "error":
                return {
                    "state": "error",
                    "interface": data["interface"],
                    "error": data["error"],
                }
            else:
                return {
                    "state": "stopped",
                    "interface": data["interface"],
                }
    except Exception as exc:
        return {"state": "unknown", "error": str(exc)}


@contextlib.contextmanager
def connect():
    conn = sqlite3.connect(DB_PATH, timeout=15.0)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def query(table, args=None, limit=25, offset=0):
    if table not in ("traffic", "alerts"):
        raise ValueError(f"Invalid table: {table}")

    args = dict(args) if args else {}
    clauses = []
    params = []

    if args.get("src_ip"):
        clauses.append("src_ip LIKE ?")
        params.append(f"%{args['src_ip']}%")
    if args.get("protocol"):
        clauses.append("protocol = ?")
        params.append(args["protocol"])
    if args.get("severity"):
        clauses.append("severity = ?")
        params.append(args["severity"])
    if table == "traffic" and args.get("label"):
        clauses.append("label = ?")
        params.append(args["label"])
    if table == "alerts" and args.get("attack_type"):
        clauses.append("attack_type = ?")
        params.append(args["attack_type"])

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    with connect() as conn:
        c = conn.cursor()
        c.execute(f"SELECT COUNT(*) FROM {table} {where}", params)
        total = c.fetchone()[0]

        c.execute(
            f"SELECT * FROM {table} {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        )
        rows = []
        for r in c.fetchall():
            d = dict(r)
            if d.get("features") and isinstance(d["features"], str):
                try:
                    d["features"] = json.loads(d["features"])
                except Exception:
                    pass
            rows.append(d)

    return {"rows": rows, "total": total}


def stats(args=None):
    with connect() as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM traffic")
        total_traffic = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM alerts")
        total_alerts = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM alerts WHERE blocked = 1")
        total_blocked = c.fetchone()[0]

        c.execute("SELECT attack_type, COUNT(*) as cnt FROM alerts GROUP BY attack_type ORDER BY cnt DESC")
        attacks = [{"attack_type": r["attack_type"], "count": r["cnt"]} for r in c.fetchall()]

    return {
        "traffic": total_traffic,
        "alerts": total_alerts,
        "total_packets": total_traffic,
        "total_alerts": total_alerts,
        "total_blocked": total_blocked,
        "attacks": attacks,
    }


def get_status():
    try:
        from ml_model import NIDSModel
        model = NIDSModel()
        det_mode = model.status
    except Exception as e:
        det_mode = f"Error loading model: {e}"

    capture = read_capture_status()

    return {
        "status": capture.get("state", "unknown"),
        "detection_mode": det_mode,
        "capture": capture,
    }


def log_traffic(src_ip, dst_ip, protocol, length, label="normal", confidence=0.0,
                source="rule", severity="info", reason=None, features=None):
    if isinstance(features, dict):
        features = json.dumps(features)
    with connect() as conn:
        conn.execute(
            "INSERT INTO traffic (timestamp, src_ip, dst_ip, protocol, length, label, confidence, source, severity, reason, features) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (time.time(), src_ip, dst_ip, protocol, length, label, confidence, source, severity, reason, features),
        )


def log_alert(src_ip, attack_type, confidence, blocked=False,
              source="rule", severity="high", reason=None, features=None):
    if isinstance(features, dict):
        features = json.dumps(features)
    with connect() as conn:
        conn.execute(
            "INSERT INTO alerts (timestamp, src_ip, attack_type, confidence, blocked, source, severity, reason, features) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (time.time(), src_ip, attack_type, confidence, int(blocked), source, severity, reason, features),
        )


def log_audit(action, ip, success=True, detail=""):
    with connect() as conn:
        conn.execute(
            "INSERT INTO audit (timestamp, action, ip, success, detail) VALUES (?, ?, ?, ?, ?)",
            (time.time(), action, ip, int(success), detail),
        )


def get_recent_traffic(limit=50):
    res = query("traffic", limit=limit)
    return [
        (r["timestamp"], r["src_ip"], r["dst_ip"], r["protocol"], r["length"], r["label"], r["confidence"])
        for r in res["rows"]
    ]


def get_recent_alerts(limit=20):
    res = query("alerts", limit=limit)
    return [
        (r["timestamp"], r["src_ip"], r["attack_type"], r["confidence"], r["blocked"])
        for r in res["rows"]
    ]


def get_stats():
    return stats()


def get_blocked_ips():
    with connect() as conn:
        rows = conn.execute("""
            SELECT src_ip,
                   MIN(timestamp) AS first_blocked,
                   MAX(timestamp) AS last_seen,
                   COUNT(*) AS alert_count,
                   attack_type
            FROM alerts
            WHERE blocked = 1
            GROUP BY src_ip
            ORDER BY last_seen DESC
        """).fetchall()
    return rows