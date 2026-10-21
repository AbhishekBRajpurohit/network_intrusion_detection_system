"""Shared packet features for live capture and PCAP analysis."""

from collections import defaultdict, deque
from math import isfinite

FEATURE_ORDER = [
    "packet_rate",
    "unique_ports",
    "syn_rate",
    "avg_packet_len",
]

WINDOW_SECONDS = 5
SCHEMA_VERSION = "source-ip-window-v3"

LABELS = (
    "normal",
    "port_scan",
    "syn_flood",
    "other_attack",
)

TIMESTAMP_TOLERANCE_SECONDS = 0.1


class FeatureExtractor:
    def __init__(
        self,
        window=WINDOW_SECONDS,
        max_sources=10000,
        max_packets=20000,
    ):
        if (
            not isfinite(window)
            or window <= 0
            or min(max_sources, max_packets) < 1
        ):
            raise ValueError("Window and capacity limits must be positive")

        self.window = window
        self.max_sources = max_sources
        self.max_packets = max_packets

        self.windows = defaultdict(deque)
        self.last_time = None
        self.last_cleanup = None
        self.timestamp_corrections = 0

    def cleanup(self, timestamp):
        for source in list(self.windows):
            packets = self.windows[source]

            if (
                not packets
                or timestamp - packets[-1][0] >= self.window
            ):
                del self.windows[source]

        self.last_cleanup = timestamp

    def update(self, src, timestamp, length, dport=None, syn=False):
        timestamp = float(timestamp)
        length = float(length)

        if (
            not isfinite(timestamp)
            or not isfinite(length)
            or length < 0
        ):
            raise ValueError("Invalid packet timestamp or length")

        corrected = False

        if self.last_time is not None and timestamp < self.last_time:
            difference = self.last_time - timestamp

            if difference > TIMESTAMP_TOLERANCE_SECONDS:
                raise ValueError(
                    f"Packet timestamp moved backwards by {difference:.6f}s; "
                    f"maximum tolerated difference is "
                    f"{TIMESTAMP_TOLERANCE_SECONDS}s"
                )

            timestamp = self.last_time
            corrected = True

        if (
            self.last_cleanup is None
            or timestamp - self.last_cleanup >= self.window
        ):
            self.cleanup(timestamp)

        if src not in self.windows and len(self.windows) >= self.max_sources:
            raise OverflowError("Source tracking capacity exceeded")

        packets = self.windows[src]

        while packets and timestamp - packets[0][0] >= self.window:
            packets.popleft()

        if len(packets) >= self.max_packets:
            raise OverflowError("Per-source packet capacity exceeded")

        packets.append((timestamp, length, dport, bool(syn)))
        self.last_time = timestamp

        if corrected:
            self.timestamp_corrections += 1

        return {
            "packet_rate": len(packets) / self.window,
            "unique_ports": len({
                packet[2]
                for packet in packets
                if packet[2] is not None
            }),
            "syn_rate": sum(packet[3] for packet in packets) / self.window,
            "avg_packet_len": (
                sum(packet[1] for packet in packets) / len(packets)
            ),
        }


def packet_record(packet):
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    layer = packet.getlayer(IP)

    if layer is None:
        layer = packet.getlayer(IPv6)

    if layer is None:
        return None

    tcp = packet.getlayer(TCP)
    udp = packet.getlayer(UDP)
    transport = tcp if tcp is not None else udp

    flags = int(tcp.flags) if tcp is not None else 0

    # This heuristic excludes likely response ports from port diversity.
    # It does not declare response-like packets safe.
    response = bool(
        flags & 16 or (flags & 4 and not flags & 2)
    )

    if udp is not None:
        response = (
            udp.sport < 1024 or udp.sport in {1900, 5353}
        ) and udp.dport >= 1024

    return {
        "timestamp": float(packet.time),
        "src_ip": layer.src,
        "dst_ip": layer.dst,
        "protocol": (
            "TCP" if tcp is not None
            else "UDP" if udp is not None
            else "OTHER"
        ),
        "length": len(packet),
        "dport": int(transport.dport) if transport is not None else None,
        "syn": bool(flags & 2 and not flags & 16),
        "is_response": response,
    }


def extract_record(extractor, record):
    port = (
        None
        if record.get("is_response", False)
        else record.get("dport")
    )

    return extractor.update(
        record["src_ip"],
        record["timestamp"],
        record["length"],
        port,
        record["syn"],
    )