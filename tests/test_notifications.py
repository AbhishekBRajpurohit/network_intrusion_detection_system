import unittest
from unittest.mock import patch, MagicMock

from utils.notifications import (
    check_and_update_cooldown,
    reset_cooldowns,
    format_alert_email,
    send_high_severity_alert,
    get_notification_config,
)


class TestNotifications(unittest.TestCase):
    def setUp(self):
        reset_cooldowns()

    def test_cooldown_enforcement(self):
        ip = "203.0.113.10"
        # First send should succeed
        can_send, rem = check_and_update_cooldown(ip, cooldown_seconds=60)
        self.assertTrue(can_send)
        self.assertEqual(rem, 0.0)

        # Immediate second check should be suppressed by cooldown
        can_send2, rem2 = check_and_update_cooldown(ip, cooldown_seconds=60)
        self.assertFalse(can_send2)
        self.assertGreater(rem2, 0.0)

        # Different IP should not be affected by first IP's cooldown
        can_send_diff, _ = check_and_update_cooldown("198.51.100.99", cooldown_seconds=60)
        self.assertTrue(can_send_diff)

    def test_format_alert_email(self):
        info = {
            "src_ip": "192.0.2.1",
            "attack_type": "syn_flood",
            "confidence": 0.95,
            "severity": "high",
            "reason": "45.0 initial SYN packets/second",
            "blocked": True,
            "features": {"packet_rate": 50, "unique_ports": 2, "syn_rate": 45},
        }
        subject, text_body, html_body = format_alert_email(info)
        self.assertIn("192.0.2.1", subject)
        self.assertIn("syn_flood", subject)
        self.assertIn("Temporarily Blocked", text_body)
        self.assertIn("45.0 initial SYN", text_body)
        self.assertIn("192.0.2.1", html_body)

    def test_dry_run_dispatch(self):
        info = {
            "src_ip": "192.0.2.2",
            "attack_type": "port_scan",
            "confidence": 0.9,
            "severity": "high",
            "reason": "20 ports scanned",
            "blocked": False,
        }
        res = send_high_severity_alert(info, dry_run=True)
        self.assertFalse(res["sent"])
        self.assertTrue(res.get("simulated"))

    @patch("smtplib.SMTP")
    @patch.dict("os.environ", {
        "ALERT_EMAIL_ENABLED": "1",
        "SMTP_HOST": "mail.example.com",
        "SMTP_PORT": "587",
        "ALERT_EMAIL_TO": "security@example.com",
        "EMAIL_COOLDOWN_SECONDS": "300",
    })
    def test_smtp_send_success(self, mock_smtp):
        instance = MagicMock()
        mock_smtp.return_value = instance

        info = {
            "src_ip": "192.0.2.3",
            "attack_type": "syn_flood",
            "confidence": 0.99,
            "severity": "high",
            "reason": "SYN flood",
            "blocked": True,
        }
        res = send_high_severity_alert(info)
        self.assertTrue(res["sent"])
        self.assertEqual(res["to"], "security@example.com")
        instance.send_message.assert_called_once()


if __name__ == "__main__":
    unittest.main()
