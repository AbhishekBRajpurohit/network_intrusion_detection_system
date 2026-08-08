# Real-Time Network Intrusion Detection System (NIDS)

A lightweight Python-based NIDS that sniffs live network traffic, extracts
behavioral features, classifies traffic using a trained ML model, shows
everything on a live dashboard, and can auto-block malicious IPs.

## Project Structure

```
nids_project/
├── app.py                # Flask web dashboard (live traffic + alerts)
├── sniffer.py             # Live packet capture + feature extraction (scapy)
├── train_model.py         # Train the ML classifier on a dataset (NSL-KDD/CICIDS2017)
├── ml_model.py             # Load trained model + predict on live features
├── utils/
│   ├── firewall.py         # Auto-block malicious IPs via iptables
│   └── logger.py           # SQLite logging of packets + alerts
├── templates/
│   └── index.html           # Dashboard HTML
├── static/
│   ├── js/dashboard.js       # Frontend polling + Chart.js graphs
│   └── css/style.css
├── models/                  # Saved trained model (.pkl) goes here
├── data/                    # Put your dataset CSV here (see below)
├── requirements.txt
└── README.md
```

## Setup

```bash
# 1. Create a virtual environment
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Linux only, for live sniffing) run with elevated privileges
#    scapy needs raw socket access to sniff packets
```

## Step 1: Get a Dataset & Train the Model

Download the **NSL-KDD** dataset (recommended for beginners — smaller and
cleaner than CICIDS2017):
https://www.unb.ca/cic/datasets/nsl.html

Put `KDDTrain+.csv` into the `data/` folder, then run:

```bash
python train_model.py
```

This trains a Random Forest classifier and saves it to `models/nids_model.pkl`.

## Step 2: Run the Dashboard + Live Sniffer

```bash
sudo python app.py        # sudo/admin needed for raw packet sniffing
```

Open your browser at **http://127.0.0.1:5000** — you'll see live traffic
stats, flagged alerts, and (optionally) auto-blocked IPs.

## Notes for Windows users

- `scapy` on Windows needs **Npcap** installed (https://npcap.com/) instead
  of libpcap.
- `iptables` auto-blocking in `utils/firewall.py` is Linux-only. On Windows,
  either comment that call out or swap it for `netsh advfirewall` commands
  (a stub is provided).
- Easiest path: run this whole project inside **WSL2** (Windows Subsystem
  for Linux) so scapy + iptables both work natively.

## How to Extend This for Your Report/Resume

- Report your model's accuracy/precision/recall on a held-out test set
  (`train_model.py` already prints these).
- Add a confusion matrix screenshot to your report — looks great and is
  standard ML-project evidence.
- Record a 30–60 second demo video/GIF of the dashboard catching a
  simulated port scan (`nmap -sS <your-ip>` from another machine/VM) — this
  is the single best thing you can put on a resume link.
- Optional stretch goals: email/Slack alert on detection, geo-IP lookup
  for attacker IPs, support for multiple network interfaces.

## Disclaimer

Only run the sniffer on networks/devices you own or have explicit
permission to monitor. Only test attacks (e.g. port scans) against your
own machines/VMs.
