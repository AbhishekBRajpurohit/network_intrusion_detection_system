import unittest
import time
from unittest.mock import patch, MagicMock
import subprocess

from utils.firewall import validate_ip, block_ip, unblock_ip, is_blocked, get_active_blocks, _active_blocks


class TestFirewall(unittest.TestCase):
    def setUp(self):
        _active_blocks.clear()

    def test_validate_ip(self):
        self.assertTrue(validate_ip("192.168.1.1"))
        self.assertTrue(validate_ip("10.0.0.254"))
        self.assertTrue(validate_ip("::1"))
        self.assertFalse(validate_ip("invalid-ip"))
        self.assertFalse(validate_ip("999.999.999.999"))
        self.assertFalse(validate_ip("; rm -rf /"))

    def test_block_invalid_ip_fails_gracefully(self):
        success = block_ip("not-an-ip")
        self.assertFalse(success)
        self.assertFalse(is_blocked("not-an-ip"))

    @patch("subprocess.run")
    def test_block_ip_elevation_failure_reported_truthfully(self, mock_run):
        # Simulate netsh/iptables failing due to elevation required
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stderr = "The requested operation requires elevation (Run as administrator)."
        mock_proc.stdout = ""
        mock_run.return_value = mock_proc

        result = block_ip("198.51.100.5", duration=60)
        self.assertFalse(result)
        self.assertFalse(is_blocked("198.51.100.5"))

    @patch("subprocess.run")
    def test_block_ip_success_and_temporary_unblock(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stderr = ""
        mock_proc.stdout = "Ok."
        mock_run.return_value = mock_proc

        test_ip = "198.51.100.77"
        result = block_ip(test_ip, duration=300)
        self.assertTrue(result)
        self.assertTrue(is_blocked(test_ip))

        blocks = get_active_blocks()
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0]["ip"], test_ip)
        self.assertGreater(blocks[0]["remaining_seconds"], 0)

        # Unblock
        unblock_res = unblock_ip(test_ip)
        self.assertTrue(unblock_res)
        self.assertFalse(is_blocked(test_ip))
        self.assertEqual(len(get_active_blocks()), 0)


if __name__ == "__main__":
    unittest.main()
