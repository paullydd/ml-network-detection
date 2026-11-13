# Machine Learning–Based Network Anomaly Detection (Prototype IDS)

A prototype intrusion detection system that combines **Windows Security event logs** with **network flows from packet captures** and uses unsupervised anomaly detection (**Isolation Forest**) to surface unusual authentication and network behavior.

The goal is to explore how log-based and flow-based features can be engineered, combined and run as a practical detection pipeline. It is a learning project, not a production IDS.

## Why

Traditional IDS tools rely on signatures and static rules. This project asks whether unsupervised machine learning can surface suspicious behavior where labeled attack data is limited or unavailable, and where it falls short.

Objectives:

- Work with real security signals: Windows event IDs and network flows
- Engineer interpretable features from logs and PCAPs
- Apply an anomaly detection model that needs no labels
- Package the pipeline as a command-line tool
- Measure honestly what the model catches and what it misses

## Quick start

```bash
git clone https://github.com/paullydd/ml-network-detection.git
cd ml-network-detection/anomaly-ids
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[all]"

anomaly-detect sample   # generate a demo capture with a hidden attack
anomaly-detect run      # logs -> pcap -> features -> predict -> report
open reports/anomaly_report.html
anomaly-detect dashboard
```

To analyze your own traffic, put captures (`.pcap` or `.pcapng`, for example saved from Wireshark) in `anomaly-ids/data/raw/pcaps/` and Windows Security logs exported as CSV in `anomaly-ids/data/raw/logs/`, then run `anomaly-detect run`.

## How it works

```
data/raw/logs/*.csv ──► logs ──► per-IP logon summary ─┐
                                                       ├─► features ──► predict ──► report / dashboard
data/raw/pcaps/*.pcap ─► pcap ──► network flows ───────┘                  │
                                                                          ▼
live network interface ─► live ──► flows scored as they finish ◄── saved model
```

**1. Windows log processing** (`anomaly-detect logs`). Loads CSV exports and keeps:

- 4624: successful logon
- 4625: failed logon
- 4688: process creation

It then summarizes them per source IP (failed logons, successful logons, accounts targeted). Output: `data/processed/logs.pkl`, `data/processed/ip_log_summary.csv`.

**2. Flow extraction** (`anomaly-detect pcap`). Reads `.pcap` and `.pcapng` files with a built-in, dependency-free parser (Ethernet, VLAN, raw IP, loopback and Linux cooked captures; IPv4 and IPv6). Packets are grouped into one-directional flows by 5-tuple, and a flow ends after 5 seconds of silence. Output: `data/processed/pcap_features.csv`.

**3. Feature building** (`anomaly-detect features`). Joins each flow to the logon activity of its source IP. The model uses 11 features:

| Feature | Meaning |
|---|---|
| `proto`, `sport`, `dport` | Protocol and ports |
| `packet_count`, `byte_count` | Size of the flow |
| `flow_duration`, `avg_interarrival` | Timing |
| `syn_count`, `ack_count` | TCP handshake behavior |
| `ip` | 1 if the source is on a private network |
| `failed_logins_from_ip` | Failed logons (4625) from the source IP |

Output: `data/processed/features.csv`.

**4. Anomaly detection** (`anomaly-detect predict`). Scales the features, trains an Isolation Forest (200 trees, contamination 0.05) and scores every flow. A score below 0 means flagged, and lower is more unusual. Each flagged flow gets a severity (Critical < -0.2, High < -0.1, Medium < -0.05, otherwise Low) and a plain-language reason built from the features furthest from normal, such as "bytes sent unusually high". Use `--use-saved` to score with the saved model instead of retraining. Output: `data/processed/predictions.csv`, `model_outputs/iforest.pkl`, `model_outputs/scaler.pkl`.

**5. Reporting** (`anomaly-detect report`). An HTML report of the most unusual flows and the sources behind them. Output: `reports/anomaly_report.html`.

**Live mode** (`sudo anomaly-detect live --iface en0`). Sniffs an interface with Scapy, builds flows with the same code as batch mode and scores each one with the saved model when it ends. Flagged flows print to the terminal, and every flow is appended to `data/live/live_predictions.csv`. Watch it with `anomaly-detect dashboard --live`. This is for experimenting, not continuous monitoring.

## Commands

| Command | What it does |
|---|---|
| `anomaly-detect sample` | Generate a demo capture with a hidden attack |
| `anomaly-detect run` | Run every batch stage in order |
| `anomaly-detect logs` / `pcap` / `features` / `predict` / `report` | Run one stage |
| `anomaly-detect predict --use-saved` | Score with the saved model |
| `anomaly-detect live --iface en0` | Score live traffic (needs sudo) |
| `anomaly-detect dashboard [--live]` | Open the Streamlit dashboard |
| `anomaly-detect --home PATH ...` | Use a different project folder |

## Results on the sample data

`anomaly-detect sample` writes about 10,000 packets of synthetic office traffic (DNS, HTTPS and file-share sessions from 17 workstations) with an attack from `192.168.1.22` that lines up with the sample Windows logs: a port scan, an RDP brute force (the 8 failed logons for `jdoe`), an RDP session after the successful logon, and a large upload to an external host.

From one run (916 flows, 46 flagged):

| Activity | Flows | Flagged |
|---|---|---|
| Exfiltration upload to 203.0.113.50 | 2 | 2 (top score, Critical) |
| RDP session after the brute force | 2 | 2 (High) |
| RDP brute-force attempts | 16 | 0 |
| Port scan (single SYN packets) | 100 | 0 |
| 5 quick SMB logon attempts from 192.168.1.34 | 10 | 0 |
| Normal background traffic | 786 | 42 (false positives, mostly large file transfers) |

**What this shows:**

- The model is good at **volume and duration outliers**: the exfiltration and the long RDP session were the top four flows.
- It misses attacks made of **many small, normal-looking flows**. Each scan probe or brute-force attempt looks like an ordinary short connection on its own. Catching those needs features that look across flows (for example, distinct destination ports per source per minute) or rule-based detection, which is what the companion [log analyzer](https://github.com/paullydd/python-log-parser) does for failed logons.
- In earlier live testing on my own network, retraining on a recent baseline capture cut false positives significantly. What counts as normal is specific to each environment.

## Limitations

- No ground-truth labels for real traffic, so evaluation outside the sample data is qualitative.
- Isolation Forest is sensitive to feature choice, scaling and the contamination setting.
- Flows are one-directional and per 5-tuple, so request and response are scored separately.
- Logons are joined to flows by source IP only, not by time.
- Live mode is single-threaded Python and isn't built for high-throughput networks.
- Not a replacement for signature-based IDS such as Suricata or Zeek.

## Roadmap

- Cross-flow features (fan-out, distinct ports per source, connection rate) to catch scans and brute force
- Time-aware joining of logon events to flows
- Labeled datasets (for example CIC-IDS2017) for detection-rate and false-positive measurement
- Zeek log input
- Model versioning and scheduled retraining

## Project layout

```
anomaly-ids/
├── anomaly_detector/
│   ├── cli.py            # anomaly-detect command
│   ├── pipeline.py       # runs the stages in order
│   ├── logs.py           # stage 1: Windows logs
│   ├── pcap.py           # stage 2: PCAP -> flows
│   ├── pcap_reader.py    # pcap/pcapng parser
│   ├── features.py       # flow building and the model's feature set (shared with live mode)
│   ├── build.py          # stage 3: join logs onto flows
│   ├── model.py          # stage 4: Isolation Forest
│   ├── report.py         # stage 5: HTML report
│   ├── live_capture.py   # live mode
│   ├── sample.py         # demo capture generator
│   └── templates/report.html
├── dashboard/            # Streamlit apps (batch and live)
├── data/raw/             # your logs and captures go here
├── tests/                # pytest suite
├── detect.sh             # same as `anomaly-detect run`
├── requirements.txt
└── setup.py
```

Run the tests with `pytest` from `anomaly-ids/`.

## Tech stack

Python, pandas, NumPy, scikit-learn, Scapy, Click, Jinja2, Streamlit, Altair, pytest

## Author

Paul DeFrain · [Portfolio](https://paullydd.github.io) · [GitHub](https://github.com/paullydd)
