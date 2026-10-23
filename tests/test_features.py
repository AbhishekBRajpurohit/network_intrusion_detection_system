"""Verify packet features and sliding-window behavior."""

import random
import unittest

from features import (
    FeatureExtractor,
    FEATURE_ORDER,
    packet_record,
    extract_record,
)


class TestFeatureExtractor(unittest.TestCase):
    def test_single_packet(self):
        result = FeatureExtractor().update(
            "a", 1000, 100, 80, True
        )

        self.assertEqual(list(result), FEATURE_ORDER)

        self.assertEqual(result, {
            "packet_rate": 0.2,
            "unique_ports": 1,
            "syn_rate": 0.2,
            "avg_packet_len": 100.0,
        })

    def test_duplicate_ports_and_partial_expiry(self):
        extractor = FeatureExtractor()

        extractor.update("a", 1000, 60, 80, True)
        extractor.update("a", 1001, 100, 80, False)
        extractor.update("a", 1002, 200, 443, True)

        # The first packet expires, but port 80 is still present.
        result = extractor.update("a", 1005, 300, 53, False)

        self.assertEqual(result["unique_ports"], 3)
        self.assertAlmostEqual(result["avg_packet_len"], 200)
        self.assertAlmostEqual(result["syn_rate"], 0.2)

        # The second port-80 packet now expires.
        result = extractor.update("a", 1006, 400, 53, False)

        self.assertEqual(result["unique_ports"], 2)
        self.assertEqual(result["avg_packet_len"], 300)

    def test_full_window_expiry(self):
        extractor = FeatureExtractor()

        extractor.update("a", 1000, 60, 80, True)
        result = extractor.update("a", 1005, 200, 443, False)

        self.assertEqual(result["packet_rate"], 0.2)
        self.assertEqual(result["syn_rate"], 0)
        self.assertEqual(result["avg_packet_len"], 200)

    def test_small_timestamp_regression(self):
        extractor = FeatureExtractor()

        extractor.update("a", 1000, 60)
        result = extractor.update("a", 999.999, 100)

        self.assertEqual(result["packet_rate"], 0.4)
        self.assertEqual(extractor.timestamp_corrections, 1)
        self.assertEqual(extractor.last_time, 1000)

    def test_large_timestamp_regression(self):
        extractor = FeatureExtractor()
        extractor.update("a", 1000, 60)

        with self.assertRaises(ValueError):
            extractor.update("a", 999, 100)

        self.assertEqual(extractor.timestamp_corrections, 0)

        result = extractor.update("a", 1001, 60)
        self.assertEqual(result["packet_rate"], 0.4)

    def test_invalid_numbers(self):
        cases = [
            (float("nan"), 60),
            (float("inf"), 60),
            (1000, -1),
            (1000, float("inf")),
        ]

        for timestamp, length in cases:
            with self.subTest(timestamp=timestamp, length=length):
                with self.assertRaises(ValueError):
                    FeatureExtractor().update(
                        "a", timestamp, length
                    )

    def test_capacity_limits(self):
        extractor = FeatureExtractor(
            max_sources=1,
            max_packets=2,
        )

        extractor.update("a", 1000, 60)
        extractor.update("a", 1001, 60)

        with self.assertRaises(OverflowError):
            extractor.update("a", 1002, 60)

        with self.assertRaises(OverflowError):
            extractor.update("b", 1002, 60)

        # Expired sources should free space.
        result = extractor.update("b", 1007, 120)

        self.assertEqual(result["packet_rate"], 0.2)
        self.assertNotIn("a", extractor.windows)

    def test_matches_reference_calculation(self):
        randomizer = random.Random(42)
        extractor = FeatureExtractor()
        history = {}
        timestamp = 1000.0

        for _ in range(300):
            timestamp += randomizer.choice(
                [0, 0.05, 0.2, 1, 6]
            )

            source = randomizer.choice(["a", "b", "c"])
            length = randomizer.randint(40, 1500)
            port = randomizer.choice([None, 53, 80, 443])
            syn = randomizer.choice([True, False])

            packets = [
                packet
                for packet in history.get(source, [])
                if timestamp - packet[0] < 5
            ]

            packets.append((timestamp, length, port, syn))
            history[source] = packets

            expected = {
                "packet_rate": len(packets) / 5,
                "unique_ports": len({
                    packet[2]
                    for packet in packets
                    if packet[2] is not None
                }),
                "syn_rate": (
                    sum(packet[3] for packet in packets) / 5
                ),
                "avg_packet_len": (
                    sum(packet[1] for packet in packets)
                    / len(packets)
                ),
            }

            actual = extractor.update(
                source, timestamp, length, port, syn
            )

            for name in FEATURE_ORDER:
                self.assertAlmostEqual(
                    actual[name],
                    expected[name],
                )

    def test_tcp_flags(self):
        from scapy.layers.inet import IP, TCP

        cases = [
            ("S", False, True),
            ("SA", True, False),
            ("PA", True, False),
            ("R", True, False),
        ]

        for flags, response, syn in cases:
            with self.subTest(flags=flags):
                packet = (
                    IP(src="192.0.2.1", dst="192.0.2.2")
                    / TCP(flags=flags)
                )

                record = packet_record(packet)

                self.assertEqual(
                    record["is_response"],
                    response,
                )
                self.assertEqual(record["syn"], syn)

    def test_udp_response_and_probe(self):
        from scapy.layers.inet import IP, UDP

        cases = [
            (53, 50000, True),
            (50000, 53, False),
        ]

        for sport, dport, expected in cases:
            packet = IP() / UDP(sport=sport, dport=dport)

            self.assertEqual(
                packet_record(packet)["is_response"],
                expected,
            )

    def test_responses_still_count_toward_packet_rate(self):
        from scapy.layers.inet import IP, TCP

        extractor = FeatureExtractor()

        for index in range(20):
            packet = (
                IP(src="192.0.2.1", dst="192.0.2.2")
                / TCP(
                    sport=443,
                    dport=50000 + index,
                    flags="PA",
                )
            )

            packet.time = 1000 + index * 0.05

            result = extract_record(
                extractor,
                packet_record(packet),
            )

        self.assertEqual(result["unique_ports"], 0)
        self.assertEqual(result["packet_rate"], 4)

    def test_scan_ports_are_counted(self):
        from scapy.layers.inet import IP, TCP

        extractor = FeatureExtractor()

        for index in range(20):
            packet = (
                IP(src="192.0.2.1", dst="192.0.2.2")
                / TCP(
                    sport=50000,
                    dport=index + 1,
                    flags="S",
                )
            )

            packet.time = 1000 + index * 0.05

            result = extract_record(
                extractor,
                packet_record(packet),
            )

        self.assertEqual(result["unique_ports"], 20)
        self.assertEqual(result["syn_rate"], 4)


if __name__ == "__main__":
    unittest.main()