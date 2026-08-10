"""
Live packet capture + lightweight feature extraction.

Uses scapy to sniff packets on a network interface, tracks per-source-IP
behavior over a sliding time window (packet rate, unique ports touched,
SYN count, etc.), and hands off feature vectors to the ML model for
classification.

Run this directly to test sniffing standalone:
    sudo python sniffer.py
It is normally imported and started from app.py.
"""

import time
import threading
from collections import defaultdict, deque

from scapy.all import sniff, IP, TCP, UDP

from utils.logger import log_traffic, log_alert
from utils.firewall import block_ip
from ml_model import NIDSModel

WINDOW_SECONDS = 5          # sliding window for behavioral features
CONFIDENCE_THRESHOLD = 0.85  # auto-block threshold
AUTO_BLOCK_ENABLED = True

# per-source-ip rolling packet timestamps + metadata for feature extraction
_ip_windows = defaultdict(lambda: deque())
_lock = threading.Lock()

model = NIDSModel()


def _extract_features(src_ip):
    """Compute simple behavioral features for src_ip over the last WINDOW_SECONDS."""
    now = time.time()
    with _lock:
        window = _ip_windows[src_ip]
        # drop old entries
        while window and now - window[0]["t"] > WINDOW_SECONDS:
            window.popleft()

        packet_count = len(window)
        unique_ports = len(set(e["dport"] for e in window if e["dport"]))
        syn_count = sum(1 for e in window if e.get("flag") == "S")
        avg_len = sum(e["len"] for e in window) / packet_count if packet_count else 0

    return {
        "packet_rate": packet_count / WINDOW_SECONDS,
        "unique_ports": unique_ports,
        "syn_rate": syn_count / WINDOW_SECONDS,
        "avg_packet_len": avg_len,
    }


def _handle_packet(pkt):
    if IP not in pkt:
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    length = len(pkt)
    proto = "OTHER"
    dport = None
    flag = None

    if TCP in pkt:
        proto = "TCP"
        dport = pkt[TCP].dport
        flags = pkt[TCP].flags
        if flags == "S":
            flag = "S"
    elif UDP in pkt:
        proto = "UDP"
        dport = pkt[UDP].dport

    with _lock:
        _ip_windows[src_ip].append({"t": time.time(), "dport": dport, "flag": flag, "len": length})

   features = _extract_features(src_ip)
    label, confidence = model.predict(features)

    # --- Safety-net rule: catch obvious scans/floods even if the trained
    # ML model (fit on proxy-scaled NSL-KDD features) misses them due to
    # feature-scale mismatch with live traffic. ---
    if features["unique_ports"] > 15 and label == "normal":
        label, confidence = "port_scan", 0.95
    elif features["syn_rate"] > 20 and label == "normal":
        label, confidence = "syn_flood", 0.95

    log_traffic(src_ip, dst_ip, proto, length, label=label, confidence=confidence)

    if label != "normal" and confidence >= CONFIDENCE_THRESHOLD:
        blocked = False
        if AUTO_BLOCK_ENABLED:
            blocked = block_ip(src_ip)
        log_alert(src_ip, label, confidence, blocked=blocked)
        print(f"[ALERT] {src_ip} flagged as '{label}' (confidence={confidence:.2f}) "
              f"blocked={blocked}")


def start_sniffing(iface=None):
    """Start sniffing in the current thread (blocking). Call from a background thread."""
    print(f"[sniffer] Starting capture on interface: {iface or 'default'}")
    sniff(iface=iface, prn=_handle_packet, store=False)


def start_sniffing_background(iface=None):
    t = threading.Thread(target=start_sniffing, args=(iface,), daemon=True)
    t.start()
    return t


if __name__ == "__main__":
    start_sniffing()