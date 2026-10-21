"""Offline PCAP analysis and labelled feature export with summaries."""

import argparse
import csv
import hashlib
import ipaddress
import json
import time

from collections import Counter
from pathlib import Path

from scapy.utils import PcapReader

from features import (
    FeatureExtractor,
    FEATURE_ORDER,
    SCHEMA_VERSION,
    WINDOW_SECONDS,
    LABELS,
    packet_record,
    extract_record,
)

from ml_model import NIDSModel


def process(path, output, label=None, session=None, src=None):
    path = Path(path)
    output = Path(output)

    if path.resolve() == output.resolve():
        raise ValueError("Output must differ from input")

    if output.exists():
        raise FileExistsError(
            f"Output already exists: {output}. Choose a new filename."
        )

    if label is not None:
        if (
            label not in LABELS
            or not session
            or not session.strip()
        ):
            raise ValueError(
                "CSV export requires a valid label "
                "and a nonempty session"
            )

    if src:
        src = str(ipaddress.ip_address(src))

    started = time.monotonic()
    digest = hashlib.sha256()

    with path.open("rb") as stream:
        for chunk in iter(
            lambda: stream.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)

    extractor = FeatureExtractor()
    model = NIDSModel() if label is None else None

    total_packets = 0
    non_ip_packets = 0
    filtered_packets = 0
    count = 0

    label_counts = Counter()

    # Exclusive creation protects previous exports.
    with output.open(
        "x",
        newline="",
        encoding="utf-8",
    ) as stream:
        try:
            writer = None

            if label is not None:
                writer = csv.DictWriter(
                    stream,
                    fieldnames=FEATURE_ORDER + [
                        "label",
                        "session",
                        "capture_sha256",
                        "schema_version",
                        "window_seconds",
                    ],
                )
                writer.writeheader()

            with PcapReader(str(path)) as reader:
                for packet in reader:
                    total_packets += 1

                    if total_packets % 10000 == 0:
                        print(
                            f"[progress] Read {total_packets:,} packets; "
                            f"exported {count:,} records so far",
                            flush=True,
                        )

                    record = packet_record(packet)

                    if record is None:
                        non_ip_packets += 1
                        continue

                    # Extract before filtering so capture timing is handled
                    # consistently with the live pipeline.
                    features = extract_record(extractor, record)

                    if src:
                        packet_source = str(
                            ipaddress.ip_address(record["src_ip"])
                        )

                        if packet_source != src:
                            filtered_packets += 1
                            continue

                    if writer is not None:
                        writer.writerow({
                            **features,
                            "label": label,
                            "session": session.strip(),
                            "capture_sha256": digest.hexdigest(),
                            "schema_version": SCHEMA_VERSION,
                            "window_seconds": WINDOW_SECONDS,
                        })

                        label_counts[label] += 1

                    else:
                        detection = model.predict(features)

                        stream.write(
                            json.dumps({
                                "mode": "offline",
                                **record,
                                "detection": detection,
                            }) + "\n"
                        )

                        label_counts[detection["label"]] += 1

                    count += 1

            if count == 0:
                raise ValueError("No matching IP packets found")

        except BaseException:
            # Remove only the incomplete export created by this call.
            stream.close()
            output.unlink(missing_ok=True)
            raise

    elapsed = time.monotonic() - started

    print()
    print("PCAP processing complete")
    print(f"Packets read: {total_packets:,}")
    print(f"Non-IP packets skipped: {non_ip_packets:,}")
    print(
        "IP packets excluded by source filter: "
        f"{filtered_packets:,}"
    )
    print(f"Records exported: {count:,}")
    print(
        "Timestamp corrections across all IP packets: "
        f"{extractor.timestamp_corrections:,}"
    )
    print(f"Elapsed time: {elapsed:.2f} seconds")

    if model is not None:
        print(f"Detection mode: {model.status}")
        print("Predicted labels for exported packet records:")
    else:
        print(
            "User-supplied labels for exported packet records "
            "(not predictions):"
        )

    for name, amount in sorted(label_counts.items()):
        print(f"  {name}: {amount:,}")

    print(f"Output: {output.resolve()}")

    return count


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument(
        "pcap",
        help="Input PCAP or PCAPNG file",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="New JSONL or CSV output filename",
    )
    parser.add_argument(
        "--label",
        choices=LABELS,
        help="Ground-truth label for CSV export",
    )
    parser.add_argument(
        "--session",
        help="Use the same ID for exports from one capture session",
    )
    parser.add_argument(
        "--src",
        help="Only export records from this source IP",
    )

    args = parser.parse_args()

    try:
        count = process(
            args.pcap,
            args.output,
            args.label,
            args.session,
            args.src,
        )

        print(f"Wrote {count:,} records to {args.output}")

    except Exception as exc:
        parser.exit(1, f"Export failed: {exc}\n")