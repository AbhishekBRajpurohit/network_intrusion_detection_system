"""One feature definition for live capture, PCAP export and training."""
from collections import defaultdict, deque
from math import isfinite

FEATURE_ORDER = ['packet_rate', 'unique_ports', 'syn_rate', 'avg_packet_len']
WINDOW_SECONDS = 5
SCHEMA_VERSION = 'source-ip-window-v3'
LABELS = ('normal', 'port_scan', 'syn_flood', 'other_attack')


class FeatureExtractor:
    def __init__(self, window=WINDOW_SECONDS, max_sources=10000, max_packets=20000):
        if not isfinite(window) or window <= 0 or min(max_sources, max_packets) < 1:
            raise ValueError('Window and capacity limits must be positive')
        self.window = window
        self.max_sources, self.max_packets = max_sources, max_packets
        self.windows = defaultdict(deque)
        self.last_time = None
        self.last_cleanup = None

    def cleanup(self, t):
        for src in list(self.windows):
            if not self.windows[src] or t - self.windows[src][-1][0] >= self.window:
                del self.windows[src]
        self.last_cleanup = t

    def update(self, src, timestamp, length, dport=None, syn=False):
        t, length = float(timestamp), float(length)
        if not isfinite(t) or not isfinite(length) or length < 0:
            raise ValueError('Invalid packet timestamp or length')
        if self.last_time is not None and t < self.last_time:
            backwards = self.last_time - t

            if backwards > 0.1:
                raise ValueError(
                    f'Packet timestamp moved backwards by {backwards:.6f}s; '
                    'maximum tolerated difference is 0.1s'
                )

            # Treat a small timing difference as the same timestamp.
            t = self.last_time
        if self.last_cleanup is None or t - self.last_cleanup >= self.window:
            self.cleanup(t)
        if src not in self.windows and len(self.windows) >= self.max_sources:
            raise OverflowError('Source tracking capacity exceeded')
        q = self.windows[src]
        while q and t - q[0][0] >= self.window:
            q.popleft()
        if len(q) >= self.max_packets:
            raise OverflowError('Per-source packet capacity exceeded')
        q.append((t, length, dport, bool(syn)))
        self.last_time = t
        return dict(zip(FEATURE_ORDER, [
            len(q) / self.window,
            len({p[2] for p in q if p[2] is not None}),
            sum(p[3] for p in q) / self.window,
            sum(p[1] for p in q) / len(q),
        ]))


def packet_record(pkt):
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    layer = pkt.getlayer(IP)
    if layer is None:
        layer = pkt.getlayer(IPv6)
    if layer is None:
        return None
    tcp, udp = pkt.getlayer(TCP), pkt.getlayer(UDP)
    transport = tcp if tcp is not None else udp
    flags = int(tcp.flags) if tcp is not None else 0
    # This heuristic only excludes ports from the scan metric.
    # ACK/response-like packets are still measured and classified.
    response = bool(flags & 16 or (flags & 4 and not flags & 2))
    if udp is not None:
        response = (udp.sport < 1024 or udp.sport in {1900, 5353}) and udp.dport >= 1024
    return {
        'timestamp': float(pkt.time), 'src_ip': layer.src, 'dst_ip': layer.dst,
        'protocol': 'TCP' if tcp is not None else 'UDP' if udp is not None else 'OTHER',
        'length': len(pkt),
        'dport': int(transport.dport) if transport is not None else None,
        'syn': bool(flags & 2 and not flags & 16), 'is_response': response,
    }


def extract_record(extractor, record):
    port = None if record.get('is_response', False) else record.get('dport')
    return extractor.update(record['src_ip'], record['timestamp'],
                            record['length'], port, record['syn'])
