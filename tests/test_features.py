import unittest
from features import FeatureExtractor, FEATURE_ORDER, WINDOW_SECONDS


class TestFeatureExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = FeatureExtractor(window=WINDOW_SECONDS)

    def test_feature_order_and_keys(self):
        feats = self.extractor.update("10.0.0.1", 1000.0, 64, dport=80, syn=False)
        for key in FEATURE_ORDER:
            self.assertIn(key, feats)

    def test_single_packet_metrics(self):
        feats = self.extractor.update("10.0.0.1", 1000.0, 100, dport=80, syn=True)
        self.assertEqual(feats["packet_rate"], 1 / WINDOW_SECONDS)
        self.assertEqual(feats["unique_ports"], 1)
        self.assertEqual(feats["syn_rate"], 1 / WINDOW_SECONDS)
        self.assertEqual(feats["avg_packet_len"], 100.0)

    def test_multiple_ports_and_syn(self):
        t = 1000.0
        for port in [80, 443, 8080]:
            feats = self.extractor.update("10.0.0.2", t, 60, dport=port, syn=True)
            t += 0.1
        self.assertEqual(feats["unique_ports"], 3)
        self.assertEqual(feats["syn_rate"], 3 / WINDOW_SECONDS)

    def test_window_expiration(self):
        # Packet at t=1000
        self.extractor.update("10.0.0.3", 1000.0, 100, dport=80, syn=False)
        # Packet at t=1006 (>5s later)
        feats = self.extractor.update("10.0.0.3", 1006.0, 200, dport=443, syn=False)
        self.assertEqual(feats["packet_rate"], 1 / WINDOW_SECONDS)
        self.assertEqual(feats["unique_ports"], 1)
        self.assertEqual(feats["avg_packet_len"], 200.0)

    def test_timestamp_regression_raises_error(self):
        self.extractor.update("10.0.0.4", 1000.0, 64)
        with self.assertRaises(ValueError):
            self.extractor.update("10.0.0.4", 999.0, 64)


if __name__ == "__main__":
    unittest.main()
