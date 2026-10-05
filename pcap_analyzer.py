"""Offline analysis and labelled feature export. Never sends or blocks anything."""
import argparse
import csv
import json
from pathlib import Path
from scapy.all import PcapReader
from features import FeatureExtractor, FEATURE_ORDER, packet_record, extract_record, SCHEMA_VERSION, WINDOW_SECONDS
from ml_model import NIDSModel


def process(path, output, label=None, session=None, src=None):
    if Path(path).resolve()==Path(output).resolve(): raise ValueError('Output must differ from input')
    extractor=FeatureExtractor()
    model=None if label is not None else NIDSModel()
    count=0
    with PcapReader(str(path)) as reader, open(output,'w',newline='',encoding='utf-8') as f:
        writer=None
        if label is not None:
            writer=csv.DictWriter(f,fieldnames=FEATURE_ORDER+['label','session','schema_version','window_seconds'])
            writer.writeheader()
        for pkt in reader:
            record=packet_record(pkt)
            if not record: continue
            features=extract_record(extractor,record)
            if src and record['src_ip']!=src: continue
            if writer:
                writer.writerow({**features,'label':label,'session':session,
                    'schema_version':SCHEMA_VERSION,'window_seconds':WINDOW_SECONDS})
            else:
                f.write(json.dumps({'mode':'offline',**record,'detection':model.predict(features)})+'\n')
            count+=1
    return count

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('pcap');p.add_argument('--output',required=True)
    p.add_argument('--label',choices=['normal','port_scan','syn_flood','other_attack'])
    p.add_argument('--session',help='Unique capture/session ID. Required with --label.')
    p.add_argument('--src',help='Only export this source IP (recommended for labelled attacker captures)')
    a=p.parse_args()
    if a.label is not None and not a.session: p.error('--session required with --label')
    print(f"Wrote {process(a.pcap,a.output,a.label,a.session,a.src)} records to {a.output}")
