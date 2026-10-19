import unittest
import json
from app import create_app
from utils import logger as db


class TestAppEndpoints(unittest.TestCase):
    def setUp(self):
        self.app = create_app({"TESTING": True})
        self.client = self.app.test_client()

    def test_unauthenticated_redirects_to_login(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login", res.headers.get("Location", ""))

    def test_unauthenticated_api_returns_401(self):
        res = self.client.get("/api/alerts")
        self.assertEqual(res.status_code, 401)

    def test_authenticated_alerts_and_pagination(self):
        with self.client.session_transaction() as sess:
            sess["username"] = "admin"
            sess["csrf"] = "token123"

        res = self.client.get("/api/alerts?page=1&limit=5")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("rows", data)
        self.assertIn("total", data)
        self.assertEqual(data["page"], 1)
        self.assertEqual(data["limit"], 5)

    def test_alert_status_triage_flow(self):
        # Insert a dummy alert to test status transitions
        db.log_alert("192.168.99.99", "port_scan", 0.95, blocked=False,
                     source="rule", severity="medium", reason="Test scan",
                     status="New")
        with db.connect() as conn:
            row = conn.execute("SELECT id FROM alerts WHERE src_ip = '192.168.99.99' ORDER BY id DESC LIMIT 1").fetchone()
            aid = row["id"]

        with self.client.session_transaction() as sess:
            sess["username"] = "admin"
            sess["csrf"] = "token123"

        # Update to Investigating
        res = self.client.post(
            f"/api/alerts/{aid}/status",
            headers={"X-CSRF-Token": "token123"},
            json={"status": "Investigating"}
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["status"], "Investigating")

        # Verify in database
        alert = db.get_alert(aid)
        self.assertEqual(alert["status"], "Investigating")

        # Update to Resolved
        res2 = self.client.post(
            f"/api/alerts/{aid}/status",
            headers={"X-CSRF-Token": "token123"},
            json={"status": "Resolved"}
        )
        self.assertEqual(res2.status_code, 200)
        self.assertEqual(db.get_alert(aid)["status"], "Resolved")

    def test_csrf_failure_on_post(self):
        with self.client.session_transaction() as sess:
            sess["username"] = "admin"
            sess["csrf"] = "correct_token"

        res = self.client.post(
            "/api/alerts/1/status",
            headers={"X-CSRF-Token": "wrong_token"},
            json={"status": "Resolved"}
        )
        self.assertEqual(res.status_code, 400)

    def test_login_rate_limiting(self):
        # Reset limiter state before test
        if hasattr(self.app, 'login_limiter'):
            self.app.login_limiter.reset()

        self.client.get("/login")
        with self.client.session_transaction() as sess:
            csrf_token = sess["csrf"]

        # 4 failed attempts should yield 200 with incorrect password error
        for _ in range(4):
            res = self.client.post("/login", data={
                "csrf": csrf_token,
                "username": "badactor",
                "password": "badpassword"
            })
            self.assertEqual(res.status_code, 200)
            self.assertIn(b"Incorrect username or password", res.data)

        # 5th attempt reaches max_attempts limit and returns HTTP 429
        res5 = self.client.post("/login", data={
            "csrf": csrf_token,
            "username": "badactor",
            "password": "badpassword"
        })
        self.assertEqual(res5.status_code, 429)
        self.assertIn(b"Too many failed login attempts", res5.data)

        # A subsequent attempt while locked out also returns 429
        res6 = self.client.post("/login", data={
            "csrf": csrf_token,
            "username": "badactor",
            "password": "badpassword"
        })
        self.assertEqual(res6.status_code, 429)
        self.assertIn(b"Too many failed login attempts", res6.data)


if __name__ == "__main__":
    unittest.main()
