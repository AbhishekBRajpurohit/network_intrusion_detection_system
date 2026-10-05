"""Shared live/PCAP features. Each source IP has a window across all destinations."""
from collections import defaultdict, deque

FEATURE_ORDER = ['packet_rate', 'unique_ports', 'syn_rate', 'avg_packet_len']
WINDOW_SECONDS = 5
SCHEMA_VERSION = 'source-ip-window-v2'

class FeatureExtractor:
    def __init__(self, window=WINDOW_SECONDS, max_sources=10000, max_packets=20000):
        self.window = window
        self.windows = defaultdict(deque)
        self.max_sources, self.max_packets = max_sources, max_packets
        self.last_cleanup = 0
        self.last_time = None

    def update(self, src, timestamp, length, dport=None, syn=False):
        t = float(timestamp)
        if self.last_time is not None and t < self.last_time:
            raise ValueError('Packet timestamps must be nondecreasing')
        self.last_time = t
        if t - self.last_cleanup >= self.window:
            self.cleanup(t)
        if src not in self.windows and len(self.windows) >= self.max_sources:
            raise OverflowError('Source tracking capacity exceeded')
        q = self.windows[src]
        while q and t - q[0][0] >= self.window:
            q.popleft()
        if len(q) >= self.max_packets:
            raise OverflowError('Per-source packet capacity exceeded')
        q.append((t, length, dport, syn))
        return dict(zip(FEATURE_ORDER, [len(q)/self.window,
            len({x[2] for x in q if x[2] is not None}),
            sum(x[3] for x in q)/self.window, sum(x[1] for x in q)/len(q)]))

    def cleanup(self, t):
        for src in list(self.windows):
            if not self.windows[src] or t-self.windows[src][-1][0] >= self.window:
                del self.windows[src]
        self.last_cleanup = t


def packet_record(pkt):
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    if layer is None:
        return None
    tcp, udp = pkt.getlayer(TCP), pkt.getlayer(UDP)
    transport = tcp if tcp is not None else udp
    return {'timestamp': float(pkt.time), 'src_ip': layer.src, 'dst_ip': layer.dst,
            'protocol': 'TCP' if tcp is not None else 'UDP' if udp is not None else 'OTHER',
            'length': len(pkt), 'dport': int(transport.dport) if transport is not None else None,
            'syn': bool(tcp is not None and int(tcp.flags) & 2 and not int(tcp.flags) & 16)}


def extract_record(extractor, record):
    return extractor.update(record['src_ip'], record['timestamp'], record['length'],
                            record['dport'], record['syn'])
