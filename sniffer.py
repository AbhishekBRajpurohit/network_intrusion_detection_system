"""
Live packet capture + lightweight feature extraction.

Uses scapy to sniff packets on a network interface, tracks per-source-IP
behavior over a sliding time window (packet rate, unique ports touched,
SYN count, etc.), and hands off feature vectors to the ML model for
classification.

Run this directly to test sniffing standalone:
    sudo python sniffer.py                    # capture on default interface
    sudo python sniffer.py --list-interfaces  # show available interfaces
    sudo python sniffer.py --iface eth0       # capture on a specific interface
It is normally imported and started from app.py.
"""

import argparse
import time
import threading
from collections import defaultdict, deque

from scapy.all import sniff, IP, TCP, UDP, get_if_list, get_if_addr, conf

from utils.logger import log_traffic, log_alert
from utils.firewall import block_ip
from ml_model import NIDSModel

WINDOW_SECONDS = 5          # sliding window for behavioral features
CONFIDENCE_THRESHOLD = 0.85  # auto-block threshold
AUTO_BLOCK_ENABLED = True
ALERT_COOLDOWN_SECONDS = 30  # don't re-alert on the same IP within this window

# per-source-ip rolling packet timestamps + metadata for feature extraction
_ip_windows = defaultdict(lambda: deque())
_lock = threading.Lock()

# tracks the last time each source IP triggered an alert, to avoid flooding
# the dashboard with a near-duplicate alert on every single packet
_last_alert_time = {}
_alert_lock = threading.Lock()

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
    pred = model.predict(features)
    if isinstance(pred, dict):
        label = pred.get("label", "normal")
        confidence = pred.get("probability")
        if confidence is None:
            confidence = 0.95 if label != "normal" else 0.5
        source = pred.get("source", "rule")
        severity = pred.get("severity", "info")
        reason = pred.get("reason", "")
    else:
        label, confidence = pred
        source, severity, reason = "ml", "info", ""

    # --- Safety-net rule: catch obvious scans/floods even if model missed them ---
    if features["unique_ports"] > 15 and label == "normal":
        label, confidence, severity = "port_scan", 0.95, "medium"
        reason = f"{features['unique_ports']} destination ports in {WINDOW_SECONDS} seconds"
    elif features["syn_rate"] > 20 and label == "normal":
        label, confidence, severity = "syn_flood", 0.95, "high"
        reason = f"{features['syn_rate']:.1f} initial SYN packets/second"

    log_traffic(
        src_ip, dst_ip, proto, length,
        label=label, confidence=confidence,
        source=source, severity=severity, reason=reason, features=features
    )

    if label != "normal" and confidence >= CONFIDENCE_THRESHOLD:
        blocked = False
        if AUTO_BLOCK_ENABLED:
            blocked = block_ip(src_ip)

        now = time.time()
        with _alert_lock:
            last_alert = _last_alert_time.get(src_ip, 0)
            should_log = (now - last_alert) >= ALERT_COOLDOWN_SECONDS
            if should_log:
                _last_alert_time[src_ip] = now

        if should_log:
            log_alert(
                src_ip, label, confidence, blocked=blocked,
                source=source, severity=severity, reason=reason, features=features
            )
            print(f"[ALERT] {src_ip} flagged as '{label}' (confidence={confidence:.2f}) "
                  f"blocked={blocked} reason={reason}")


def start_sniffing(iface=None):
    """Start sniffing in the current thread (blocking). Call from a background thread."""
    print(f"[sniffer] Starting capture on interface: {iface or 'default'}")
    sniff(iface=iface, prn=_handle_packet, store=False)


def start_sniffing_background(iface=None):
    t = threading.Thread(target=start_sniffing, args=(iface,), daemon=True)
    t.start()
    return t


def list_interfaces():
    """Print a table of available network interfaces with their IP addresses."""
    interfaces = get_if_list()
    default_iface = getattr(conf, "iface", None)

    # On Windows, scapy's IFACES dict maps raw device names to objects with a
    # human-readable .name or .description.  Build a lookup so we can display
    # both the friendly name and the raw device path.
    friendly = {}
    try:
        from scapy.all import IFACES  # type: ignore[attr-defined]
        for iface_obj in IFACES.values():
            raw = getattr(iface_obj, "network_name", None)
            name = getattr(iface_obj, "name", "")
            desc = getattr(iface_obj, "description", "")
            display = name or desc or ""
            if raw and display:
                friendly[raw] = display
    except Exception:
        pass  # non-Windows or older scapy — friendly names simply unavailable

    print(f"\n{'#':<4} {'Interface':<30} {'IP Address':<18} {'Note'}")
    print("-" * 75)
    for idx, iface in enumerate(interfaces, 1):
        try:
            addr = get_if_addr(iface)
        except Exception:
            addr = "(unavailable)"
        note = "<-- default" if str(iface) == str(default_iface) else ""
        label = friendly.get(iface, iface)
        print(f"{idx:<4} {label:<30} {addr:<18} {note}")
        # If we have a friendly name, also show the raw device path for use with --iface
        if label != iface:
            print(f"     ({iface})")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="NIDS live packet sniffer — capture and classify network traffic.",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit.",
    )
    parser.add_argument(
        "--iface",
        type=str,
        default=None,
        metavar="NAME",
        help="Network interface to capture on (e.g. eth0, Wi-Fi).  "
             "Use --list-interfaces to see choices.",
    )
    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
    else:
        start_sniffing(iface=args.iface)