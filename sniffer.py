"""Live capture with shared features and periodic capture statistics."""

import argparse
import threading
import time

from scapy.all import AsyncSniffer, conf, get_if_addr, get_if_list

from features import FeatureExtractor, packet_record, extract_record
from ml_model import NIDSModel

from utils.logger import (
    init_db,
    log_traffic,
    log_alert,
    update_capture_status,
    read_capture_status,
)

from utils.notifications import notify_high_severity_async


CONFIDENCE_THRESHOLD = 0.85
ALERT_COOLDOWN_SECONDS = 30
SUMMARY_INTERVAL_SECONDS = 10

_run_lock = threading.Lock()
_metrics_lock = threading.Lock()

_extractor = FeatureExtractor()
_last_alert_time = {}

_capture_metrics = {
    "packets": 0,
    "alerts": 0,
}

model = None


def get_capture_status():
    return read_capture_status()


def _handle_packet(packet):
    record = packet_record(packet)

    if record is None:
        return

    if model is None:
        raise RuntimeError("Detection model has not been initialized")

    features = extract_record(_extractor, record)
    prediction = model.predict(features)

    label = prediction["label"]
    confidence = prediction["probability"]
    source = prediction["source"]
    severity = prediction["severity"]
    reason = prediction["reason"]

    log_traffic(
        record["src_ip"],
        record["dst_ip"],
        record["protocol"],
        record["length"],
        label=label,
        confidence=confidence,
        source=source,
        severity=severity,
        reason=reason,
        features=features,
    )

    with _metrics_lock:
        _capture_metrics["packets"] += 1

    now = time.monotonic()

    for key, when in list(_last_alert_time.items()):
        if now - when >= ALERT_COOLDOWN_SECONDS:
            del _last_alert_time[key]

    should_alert = label != "normal" and (
        source == "rule"
        or (
            confidence is not None
            and confidence >= CONFIDENCE_THRESHOLD
        )
    )

    key = (record["src_ip"], label, source)

    if not should_alert or key in _last_alert_time:
        return

    log_alert(
        record["src_ip"],
        label,
        confidence,
        blocked=False,
        source=source,
        severity=severity,
        reason=reason,
        features=features,
    )

    with _metrics_lock:
        _capture_metrics["alerts"] += 1

    _last_alert_time[key] = now

    print(
        f"[ALERT] {record['src_ip']} {label}: {reason}",
        flush=True,
    )

    if severity == "high":
        try:
            notify_high_severity_async({
                "src_ip": record["src_ip"],
                "attack_type": label,
                "confidence": confidence,
                "source": source,
                "severity": severity,
                "reason": reason,
                "features": features,
                "blocked": False,
                "timestamp": time.time(),
            })

        except Exception as exc:
            print(
                f"[notifications] Could not queue notification: {exc}",
                flush=True,
            )


def start_sniffing(iface=None):
    global model, _extractor

    if not _run_lock.acquire(blocking=False):
        raise RuntimeError("Capture is already running in this process")

    worker = None
    error = None
    interface = None

    callback_errors = []
    ready = threading.Event()
    cancelled = threading.Event()

    def handle(packet):
        if callback_errors or cancelled.is_set():
            return

        try:
            _handle_packet(packet)

        except Exception as exc:
            # Preserve callback errors instead of letting Scapy hide them.
            callback_errors.append(exc)

    def on_started():
        ready.set()

        if cancelled.is_set() and worker is not None:
            worker.stop(join=False)

    try:
        interface = str(iface or conf.iface)

        init_db()

        model = NIDSModel()
        _extractor = FeatureExtractor()
        _last_alert_time.clear()

        with _metrics_lock:
            _capture_metrics.update(packets=0, alerts=0)

        update_capture_status("stopped", interface=interface)

        worker = AsyncSniffer(
            iface=iface,
            prn=handle,
            store=False,
            started_callback=on_started,
        )

        worker.start()

        deadline = time.monotonic() + 15

        while not ready.wait(0.1):
            if worker.exception:
                raise worker.exception

            if time.monotonic() >= deadline:
                raise TimeoutError(
                    "Capture interface did not become ready"
                )

        started = time.time()

        print(
            f"[sniffer] Capturing on {interface}; alert-only mode",
            flush=True,
        )
        print(f"[sniffer] {model.status}", flush=True)
        print(
            "[sniffer] Rule thresholds: "
            f"SYN rate >{model.syn_rate_threshold:g}/s; "
            f"destination ports >{model.port_scan_threshold}",
            flush=True,
        )

        next_heartbeat = 0
        last_summary_time = time.monotonic()
        last_packet_count = 0

        while True:
            if callback_errors:
                raise callback_errors[0]

            if worker.exception:
                raise worker.exception

            if not worker.running:
                raise RuntimeError(
                    "Capture worker stopped unexpectedly"
                )

            now = time.monotonic()

            if now >= next_heartbeat:
                update_capture_status(
                    "running",
                    interface=interface,
                    started_at=started,
                )
                next_heartbeat = now + 2

            elapsed = now - last_summary_time

            if elapsed >= SUMMARY_INTERVAL_SECONDS:
                with _metrics_lock:
                    packet_count = _capture_metrics["packets"]
                    alert_count = _capture_metrics["alerts"]

                processing_rate = (
                    packet_count - last_packet_count
                ) / elapsed

                print(
                    "[capture summary] "
                    f"IP packets processed={packet_count} | "
                    f"processing rate={processing_rate:.1f}/s | "
                    f"alerts logged={alert_count} | "
                    f"timestamp corrections="
                    f"{_extractor.timestamp_corrections}",
                    flush=True,
                )

                last_packet_count = packet_count
                last_summary_time = now

            time.sleep(0.1)

    except KeyboardInterrupt:
        print("\n[sniffer] Stopping capture", flush=True)

    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        print(f"[sniffer] Capture error: {error}", flush=True)
        raise

    finally:
        cancelled.set()

        try:
            if (
                worker is not None
                and worker.running
                and ready.is_set()
            ):
                worker.stop()

        except Exception as exc:
            error = error or f"Capture shutdown failed: {exc}"

        # Include an error raised just before shutdown.
        if callback_errors and error is None:
            exc = callback_errors[0]
            error = f"{type(exc).__name__}: {exc}"

        try:
            update_capture_status(
                "error" if error else "stopped",
                interface=interface,
                error=error,
            )

        except Exception as exc:
            print(
                f"[sniffer] Could not save final status: {exc}",
                flush=True,
            )

        finally:
            _run_lock.release()


def start_sniffing_background(iface=None):
    thread = threading.Thread(
        target=start_sniffing,
        args=(iface,),
        daemon=True,
    )
    thread.start()
    return thread


def list_interfaces():
    for number, interface in enumerate(get_if_list(), 1):
        try:
            address = get_if_addr(interface)
        except Exception:
            address = "unavailable"

        try:
            name = conf.ifaces.dev_from_networkname(interface).name
        except Exception:
            name = str(interface)

        print(f"{number}. {name}  {address}")
        print(f"   {interface}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List capture interfaces and exit",
    )
    parser.add_argument(
        "--iface",
        help="Interface name or device path",
    )

    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
    else:
        try:
            start_sniffing(args.iface)
        except Exception:
            raise SystemExit(1)