
"""Offline JSONL analysis or ground-truth labelled CSV export."""
import argparse
import csv
import hashlib
import ipaddress
import json
from pathlib import Path
from scapy.utils import PcapReader
from features import (FeatureExtractor, FEATURE_ORDER, SCHEMA_VERSION,
                      WINDOW_SECONDS, LABELS, packet_record, extract_record)
from ml_model import NIDSModel


def process(path, output, label=None, session=None, src=None):
    path, output = Path(path), Path(output)
    if path.resolve() == output.resolve():
        raise ValueError('Output must differ from input')
    if label is not None and (label not in LABELS or not session or not session.strip()):
        raise ValueError('CSV export requires a valid label and a nonempty session')
    if src:
        src = str(ipaddress.ip_address(src))
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    extractor = FeatureExtractor()
    model = NIDSModel() if label is None else None
    count = 0
    # Exclusive creation prevents accidental replacement of previous exports.
    with output.open('x', newline='', encoding='utf-8') as stream:
        try:
            writer = None
            if label is not None:
                writer = csv.DictWriter(stream, fieldnames=FEATURE_ORDER +
                    ['label', 'session', 'capture_sha256', 'schema_version', 'window_seconds'])
                writer.writeheader()
            with PcapReader(str(path)) as reader:
                for packet in reader:
                    record = packet_record(packet)
                    if record is None:
                        continue
                    features = extract_record(extractor, record)
                    if src and str(ipaddress.ip_address(record['src_ip'])) != src:
                        continue
                    if writer is not None:
                        writer.writerow({**features, 'label': label, 'session': session.strip(),
                            'capture_sha256': digest.hexdigest(),
                            'schema_version': SCHEMA_VERSION, 'window_seconds': WINDOW_SECONDS})
                    else:
                        stream.write(json.dumps({'mode': 'offline', **record,
                            'detection': model.predict(features)}) + '\n')
                    count += 1
            if not count:
                raise ValueError('No matching IP packets found')
        except BaseException:
            stream.close()
            output.unlink(missing_ok=True)
            raise
    return count


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pcap')
    parser.add_argument('--output', required=True)
    parser.add_argument('--label', choices=LABELS)
    parser.add_argument('--session', help='Same ID for exports from the same capture session')
    parser.add_argument('--src', help='Only export this source IP')
    args = parser.parse_args()
    try:
        count = process(args.pcap, args.output, args.label, args.session, args.src)
        print(f'Wrote {count} records to {args.output}')
    except Exception as exc:
        parser.exit(1, f'Export failed: {exc}\n')

