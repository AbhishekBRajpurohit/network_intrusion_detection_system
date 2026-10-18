import unittest
from features import FeatureExtractor, FEATURE_ORDER, WINDOW_SECONDS, packet_record, extract_record


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

    def test_tcp_response_traffic_classification(self):
        from scapy.layers.inet import IP, TCP
        # SYN probe (scan attempt)
        syn_pkt = IP(src="192.168.1.99", dst="192.168.1.50") / TCP(sport=50000, dport=80, flags="S")
        syn_rec = packet_record(syn_pkt)
        self.assertFalse(syn_rec["is_response"])
        self.assertTrue(syn_rec["syn"])
        self.assertEqual(syn_rec["dport"], 80)

        # SYN-ACK response
        sa_pkt = IP(src="192.168.1.1", dst="192.168.1.50") / TCP(sport=80, dport=50000, flags="SA")
        sa_rec = packet_record(sa_pkt)
        self.assertTrue(sa_rec["is_response"])
        self.assertFalse(sa_rec["syn"])

        # PSH-ACK data response
        pa_pkt = IP(src="192.168.1.1", dst="192.168.1.50") / TCP(sport=443, dport=50001, flags="PA")
        pa_rec = packet_record(pa_pkt)
        self.assertTrue(pa_rec["is_response"])

        # RST response
        rst_pkt = IP(src="192.168.1.1", dst="192.168.1.50") / TCP(sport=8080, dport=50002, flags="R")
        rst_rec = packet_record(rst_pkt)
        self.assertTrue(rst_rec["is_response"])

    def test_udp_response_vs_scan_classification(self):
        from scapy.layers.inet import IP, UDP
        # DNS response from router (sport 53 -> ephemeral dport)
        dns_resp = IP(src="192.168.1.1", dst="192.168.1.50") / UDP(sport=53, dport=52345)
        resp_rec = packet_record(dns_resp)
        self.assertTrue(resp_rec["is_response"])

        # UDP probe (ephemeral sport -> target dport 53)
        udp_probe = IP(src="192.168.1.99", dst="192.168.1.50") / UDP(sport=52345, dport=53)
        probe_rec = packet_record(udp_probe)
        self.assertFalse(probe_rec["is_response"])

    def test_router_response_traffic_does_not_inflate_unique_ports(self):
        from scapy.layers.inet import IP, TCP
        ext = FeatureExtractor(window=WINDOW_SECONDS)
        t = 1000.0
        # Gateway sends 20 HTTP response packets to 20 different client ephemeral ports
        for p in range(50000, 50020):
            pkt = IP(src="192.168.1.1", dst="192.168.1.50") / TCP(sport=443, dport=p, flags="PA")
            rec = packet_record(pkt)
            rec["timestamp"] = t
            feats = extract_record(ext, rec)
            t += 0.05
        # Response ports are excluded from unique_ports scanning metric
        self.assertEqual(feats["unique_ports"], 0)
        self.assertEqual(feats["packet_rate"], 20 / WINDOW_SECONDS)

    def test_actual_scanner_inflates_unique_ports(self):
        from scapy.layers.inet import IP, TCP
        ext = FeatureExtractor(window=WINDOW_SECONDS)
        t = 1000.0
        # Attacker scans 20 different target destination ports with SYN probes
        for p in range(1, 21):
            pkt = IP(src="10.0.0.99", dst="10.0.0.1") / TCP(sport=55555, dport=p, flags="S")
            rec = packet_record(pkt)
            rec["timestamp"] = t
            feats = extract_record(ext, rec)
            t += 0.05
        self.assertEqual(feats["unique_ports"], 20)
        self.assertEqual(feats["syn_rate"], 20 / WINDOW_SECONDS)


if __name__ == "__main__":
    unittest.main()

