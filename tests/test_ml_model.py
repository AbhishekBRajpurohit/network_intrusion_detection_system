import unittest
from ml_model import NIDSModel
from features import FEATURE_ORDER, SCHEMA_VERSION, WINDOW_SECONDS


class TestMLModel(unittest.TestCase):
    def setUp(self):
        self.model = NIDSModel()

    def test_syn_flood_rule(self):
        # syn_rate > 20
        features = {
            "packet_rate": 30.0,
            "unique_ports": 1,
            "syn_rate": 25.0,
            "avg_packet_len": 60.0,
        }
        pred = self.model.predict(features)
        self.assertEqual(pred["label"], "syn_flood")
        self.assertEqual(pred["severity"], "high")
        self.assertEqual(pred["source"], "rule")
        self.assertIn("initial SYN packets/second", pred["reason"])

    def test_port_scan_rule(self):
        # unique_ports > 15
        features = {
            "packet_rate": 10.0,
            "unique_ports": 22,
            "syn_rate": 2.0,
            "avg_packet_len": 60.0,
        }
        pred = self.model.predict(features)
        self.assertEqual(pred["label"], "port_scan")
        self.assertEqual(pred["severity"], "medium")
        self.assertEqual(pred["source"], "rule")
        self.assertIn("destination ports", pred["reason"])

    def test_normal_traffic(self):
        features = {
            "packet_rate": 2.0,
            "unique_ports": 2,
            "syn_rate": 0.5,
            "avg_packet_len": 120.0,
        }
        pred = self.model.predict(features)
        self.assertEqual(pred["label"], "normal")
        self.assertEqual(pred["severity"], "info")


if __name__ == "__main__":
    unittest.main()
