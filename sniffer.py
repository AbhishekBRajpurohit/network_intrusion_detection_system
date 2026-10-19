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

from scapy.all import sniff, get_if_list, get_if_addr, conf

from features import FeatureExtractor, packet_record, extract_record
from utils.logger import log_traffic, log_alert, update_capture_status, read_capture_status
from utils.firewall import block_ip
from utils.notifications import notify_high_severity_async
from ml_model import NIDSModel

CONFIDENCE_THRESHOLD = 0.85  # auto-block threshold
AUTO_BLOCK_ENABLED = True
ALERT_COOLDOWN_SECONDS = 30  # don't re-alert on the same IP within this window

# Shared feature extractor (replaces the old hand-rolled _ip_windows dict)
_extractor = FeatureExtractor()
_extractor_lock = threading.Lock()

# tracks the last time each source IP triggered an alert, to avoid flooding
# the dashboard with a near-duplicate alert on every single packet
_last_alert_time = {}
_alert_lock = threading.Lock()

model = NIDSModel()

# ---- in-memory capture state ----
_capture_state = "stopped"   # "running" | "stopped" | "error"
_capture_iface = None        # interface name while running
_capture_error = None        # last error message, if any
_capture_started = None      # time.time() when capture began
_state_lock = threading.Lock()


def get_capture_status():
    """Return the current capture state dict (used by the /api/status endpoint)."""
    with _state_lock:
        if _capture_state == "running":
            info = {
                "state": "running",
                "interface": _capture_iface,
            }
            if _capture_started is not None:
                info["uptime_seconds"] = round(time.time() - _capture_started, 1)
            return info
        elif _capture_state == "error":
            return {
                "state": "error",
                "interface": _capture_iface,
                "error": _capture_error,
            }

    # Cross-process fallback (e.g. Flask app checking standalone sniffer)
    return read_capture_status()


def _handle_packet(pkt):
    record = packet_record(pkt)
    if record is None:
        return

    # Response traffic (ACK, PSH-ACK, SYN-ACK, server UDP replies) is logged
    # but excluded from threat detection. Counting response packets would inflate
    # scan-detection metrics (packet_rate, unique_ports, syn_rate) for gateways
    # and servers that legitimately send high volumes of response traffic.
    if record.get('is_response', False):
        log_traffic(
            record["src_ip"], record["dst_ip"], record["protocol"], record["length"],
            label="normal", confidence=None,
            source="skip", severity="info",
            reason="Response traffic — excluded from scan detection",
            features={}
        )
        return

    with _extractor_lock:
        # Avoid dropping packets if network device reports tiny sub-microsecond timestamp jitter
        if _extractor.last_time is not None and record["timestamp"] < _extractor.last_time:
            record["timestamp"] = _extractor.last_time
        try:
            features = extract_record(_extractor, record)
        except (ValueError, OverflowError):
            return

    pred = model.predict(features)
    label = pred.get("label", "normal")
    source = pred.get("source", "rule")
    severity = pred.get("severity", "info")
    reason = pred.get("reason", "")
    # Rule detections do not produce probabilities; preserve None for rule matches.
    confidence = pred.get("probability")

    log_traffic(
        record["src_ip"], record["dst_ip"], record["protocol"], record["length"],
        label=label, confidence=confidence,
        source=source, severity=severity, reason=reason, features=features
    )

    is_rule = (source == "rule")
    should_alert = False
    if label != "normal":
        if is_rule:
            # Deterministic rule triggered
            should_alert = True
        elif confidence is not None and confidence >= CONFIDENCE_THRESHOLD:
            # ML detection met probability threshold
            should_alert = True

    if should_alert:
        blocked = False
        if AUTO_BLOCK_ENABLED:
            blocked = block_ip(record["src_ip"])

        now = time.time()
        with _alert_lock:
            last_alert = _last_alert_time.get(record["src_ip"], 0)
            should_log = (now - last_alert) >= ALERT_COOLDOWN_SECONDS
            if should_log:
                _last_alert_time[record["src_ip"]] = now

        if should_log:
            log_alert(
                record["src_ip"], label, confidence, blocked=blocked,
                source=source, severity=severity, reason=reason, features=features
            )
            conf_str = f"confidence={confidence:.2f}" if confidence is not None else "source=rule"
            print(f"[ALERT] {record['src_ip']} flagged as '{label}' ({conf_str}) "
                  f"blocked={blocked} reason={reason}")

            if severity == "high":
                notify_high_severity_async({
                    "src_ip": record["src_ip"],
                    "attack_type": label,
                    "confidence": confidence,
                    "source": source,
                    "severity": severity,
                    "reason": reason,
                    "features": features,
                    "blocked": blocked,
                    "timestamp": now,
                })


def start_sniffing(iface=None):
    """Start sniffing in the current thread (blocking). Call from a background thread."""
    global _capture_state, _capture_iface, _capture_error, _capture_started

    chosen_iface = iface or "default"
    started = time.time()
    with _state_lock:
        _capture_state = "running"
        _capture_iface = chosen_iface
        _capture_error = None
        _capture_started = started

    update_capture_status("running", interface=chosen_iface, started_at=started)

    stop_heartbeat = threading.Event()

    def _heartbeat():
        while not stop_heartbeat.wait(2.0):
            update_capture_status("running", interface=chosen_iface, started_at=started)

    hb_thread = threading.Thread(target=_heartbeat, daemon=True)
    hb_thread.start()

    print(f"[sniffer] Starting capture on interface: {chosen_iface}")
    try:
        sniff(iface=iface, prn=_handle_packet, store=False)
    except Exception as exc:
        err_msg = f"{type(exc).__name__}: {exc}"
        with _state_lock:
            _capture_state = "error"
            _capture_error = err_msg
        update_capture_status("error", interface=chosen_iface, error=err_msg)
        print(f"[sniffer] Capture error: {err_msg}")
        raise
    finally:
        stop_heartbeat.set()
        with _state_lock:
            if _capture_state != "error":
                _capture_state = "stopped"
                update_capture_status("stopped", interface=chosen_iface)


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