"""Dashboard and authentication tests using a temporary SQLite database."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from werkzeug.security import generate_password_hash
from utils import logger as db


class TestAppEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password = "Nids-test-password-2026!"
        cls.password_hash = generate_password_hash(cls.password)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)

        database = str(Path(temporary.name) / "test.sqlite3")

        database_patch = patch.object(db, "DB_PATH", database)
        database_patch.start()
        self.addCleanup(database_patch.stop)

        # app.py creates an app during import.
        # Patch the database BEFORE importing it.
        from app import create_app

        self.app = create_app({
            "TESTING": True,
            "SECRET_KEY": "test-only-session-secret",
            "SESSION_COOKIE_SECURE": False,
        })

        self.client = self.app.test_client()

        with db.connect() as connection:
            connection.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                ("admin", self.password_hash),
            )

    def csrf_token(self):
        self.client.get("/login")

        with self.client.session_transaction() as session:
            return session["csrf"]

    def authenticate(self):
        with self.client.session_transaction() as session:
            session["username"] = "admin"
            session["csrf"] = "test-csrf-token"

    def create_alert(self):
        db.log_alert(
            "192.0.2.10",
            "port_scan",
            None,
            blocked=False,
            source="rule",
            severity="medium",
            reason="Synthetic test incident",
            status="New",
        )

        with db.connect() as connection:
            return connection.execute(
                "SELECT id FROM alerts ORDER BY id DESC LIMIT 1"
            ).fetchone()["id"]

    def test_unauthenticated_redirects_to_login(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_unauthenticated_api_returns_401(self):
        response = self.client.get("/api/alerts")

        self.assertEqual(response.status_code, 401)

    def test_authenticated_alerts_and_pagination(self):
        for _ in range(3):
            self.create_alert()

        self.authenticate()

        response = self.client.get("/api/alerts?page=2&limit=2")

        self.assertEqual(response.status_code, 200)

        data = response.get_json()

        self.assertEqual(data["total"], 3)
        self.assertEqual(len(data["rows"]), 1)
        self.assertEqual(data["page"], 2)
        self.assertEqual(data["limit"], 2)

    def test_alert_status_triage_flow(self):
        alert_id = self.create_alert()
        self.authenticate()

        for status in ("Investigating", "Resolved"):
            response = self.client.post(
                f"/api/alerts/{alert_id}/status",
                headers={"X-CSRF-Token": "test-csrf-token"},
                json={"status": status},
            )

            self.assertEqual(response.status_code, 200)
            self.assertEqual(db.get_alert(alert_id)["status"], status)

    def test_csrf_failure_on_post(self):
        alert_id = self.create_alert()
        self.authenticate()

        response = self.client.post(
            f"/api/alerts/{alert_id}/status",
            headers={"X-CSRF-Token": "incorrect-token"},
            json={"status": "Resolved"},
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(db.get_alert(alert_id)["status"], "New")

    def test_invalid_alert_status_does_not_change_record(self):
        alert_id = self.create_alert()
        self.authenticate()

        response = self.client.post(
            f"/api/alerts/{alert_id}/status",
            headers={"X-CSRF-Token": "test-csrf-token"},
            json={"status": "Deleted"},
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(db.get_alert(alert_id)["status"], "New")

    def test_login_page_contains_csrf_and_accessible_fields(self):
        response = self.client.get("/login")

        self.assertEqual(response.status_code, 200)

        for markup in (
            b'name="csrf"',
            b'for="username"',
            b'for="password"',
            b'autocomplete="current-password"',
            b'class="skip-link"',
        ):
            self.assertIn(markup, response.data)

    def test_login_without_csrf_is_rejected(self):
        self.client.get("/login")

        response = self.client.post(
            "/login",
            data={
                "username": "admin",
                "password": self.password,
            },
        )

        self.assertEqual(response.status_code, 400)

        with self.client.session_transaction() as session:
            self.assertNotIn("username", session)

    def test_successful_login_rotates_csrf_token(self):
        original_token = self.csrf_token()

        response = self.client.post(
            "/login",
            data={
                "csrf": original_token,
                "username": "admin",
                "password": self.password,
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")

        with self.client.session_transaction() as session:
            self.assertEqual(session["username"], "admin")
            self.assertNotEqual(session["csrf"], original_token)

        self.assertEqual(
            self.client.get("/api/alerts").status_code,
            200,
        )

    def test_failed_login_never_echoes_password(self):
        password = "wrong-private-password"

        response = self.client.post(
            "/login",
            data={
                "csrf": self.csrf_token(),
                "username": "admin",
                "password": password,
            },
        )

        self.assertEqual(response.status_code, 200)

        self.assertIn(
            b"Incorrect username or password",
            response.data,
        )

        self.assertNotIn(password.encode(), response.data)

        with self.client.session_transaction() as session:
            self.assertNotIn("username", session)

    def test_login_rate_limiting(self):
        token = self.csrf_token()

        for attempt in range(6):
            response = self.client.post(
                "/login",
                data={
                    "csrf": token,
                    "username": "unknown-user",
                    "password": "incorrect-password",
                },
            )

            expected = 200 if attempt < 4 else 429
            self.assertEqual(response.status_code, expected)

        self.assertIn(
            b"Too many failed login attempts",
            response.data,
        )

    def test_logout_removes_authenticated_session(self):
        self.authenticate()

        response = self.client.post(
            "/logout",
            data={"csrf": "test-csrf-token"},
        )

        self.assertEqual(response.status_code, 302)

        self.assertEqual(
            self.client.get("/api/alerts").status_code,
            401,
        )

    def test_login_response_has_security_headers(self):
        response = self.client.get("/login")

        self.assertEqual(
            response.headers["Cache-Control"],
            "no-store",
        )

        self.assertEqual(
            response.headers["X-Frame-Options"],
            "DENY",
        )

        self.assertIn(
            "form-action 'self'",
            response.headers["Content-Security-Policy"],
        )

    def seed_filter_records(self):
        with db.connect() as connection:
            connection.executemany(
                "INSERT INTO traffic(timestamp,src_ip,dst_ip,protocol,label) VALUES(?,?,?,?,?)",
                [(100, "192.0.2.10", "198.51.100.1", "TCP", "normal"),
                 (200, "192.0.2.20", "198.51.100.2", "UDP", "normal"),
                 (300, "192.0.2.10", "198.51.100.3", "TCP", "port_scan")],
            )
            connection.executemany(
                "INSERT INTO alerts(timestamp,src_ip,attack_type,blocked,status) VALUES(?,?,?,?,?)",
                [(100, "192.0.2.10", "port_scan", 0, "New"),
                 (200, "192.0.2.20", "syn_flood", 1, "Resolved"),
                 (300, "192.0.2.10", "port_scan", 1, "Investigating")],
            )

    def test_stats_match_filtered_table_counts(self):
        self.seed_filter_records()
        filters = {"ip": "192.0.2.10", "start_date": "150", "end_date": "350"}
        summary = db.stats(filters)
        self.assertEqual(summary["traffic"], 1)
        self.assertEqual(summary["alerts"], 1)
        self.assertEqual(summary["total_blocked"], 1)
        self.assertEqual(summary["attacks"], [{"attack_type": "port_scan", "count": 1}])
        for table in ("traffic", "alerts"):
            self.assertEqual(summary[table], db.query(table, filters)["total"])

    def test_stats_endpoint_honors_status(self):
        self.seed_filter_records()
        self.authenticate()
        with patch("utils.firewall.get_active_blocks", return_value=[]):
            response = self.client.get("/api/stats?status=Resolved")
        self.assertEqual(response.status_code, 200)
        summary = response.get_json()
        self.assertEqual(summary["alerts"], 1)
        self.assertEqual(summary["traffic"], 3)
        self.assertEqual(summary["total_blocked"], 1)

    def test_protocol_filter_does_not_query_missing_alert_column(self):
        self.seed_filter_records()
        self.assertEqual(db.query("traffic", {"protocol": "TCP"})["total"], 2)
        self.assertEqual(db.query("alerts", {"protocol": "TCP"})["total"], 3)
        self.assertEqual(db.stats({"protocol": "TCP"})["traffic"], 2)

    def test_invalid_date_filters_return_400(self):
        self.authenticate()
        for query in ("start_date=invalid", "end_date=nan", "start_date=inf",
                      "start_date=300&end_date=100"):
            for endpoint in ("/api/traffic", "/api/alerts", "/export/alerts.csv"):
                with self.subTest(query=query, endpoint=endpoint):
                    response = self.client.get(endpoint + "?" + query)
                    self.assertEqual(response.status_code, 400)
                    self.assertIn("error", response.get_json())

    def test_date_only_end_includes_fractional_last_second(self):
        start = db._parse_date("2026-01-01")
        with db.connect() as connection:
            connection.executemany(
                "INSERT INTO traffic(timestamp,src_ip) VALUES(?,?)",
                [(start + 86399.5, "192.0.2.10"), (start + 86400, "192.0.2.10")],
            )
        self.assertEqual(db.query("traffic", {"end_date": "2026-01-01"})["total"], 1)

    def test_stats_no_matches_and_epoch_zero(self):
        self.seed_filter_records()
        summary = db.stats({"end_date": "0"})
        self.assertEqual(summary["traffic"], 0)
        self.assertEqual(summary["alerts"], 0)
        self.assertEqual(summary["attacks"], [])
        self.assertEqual(db._parse_date(0), 0)

    def test_database_initialization_preserves_records(self):
        self.seed_filter_records()
        db.init_db()
        db.init_db()
        self.assertEqual(db.query("traffic")["total"], 3)
        self.assertEqual(db.query("alerts")["total"], 3)


if __name__ == "__main__":
    unittest.main()