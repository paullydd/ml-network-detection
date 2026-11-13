"""Live mode: sniff an interface, build flows as packets arrive, score each
finished flow with the saved model and append the result to a CSV that the live
dashboard reads.

Needs Scapy and permission to capture packets (run with sudo on macOS/Linux).
"""
import csv
import time

import pandas as pd

from . import paths
from .features import FEATURE_ORDER, FlowTable, flow_features, severity
from .model import load

LIVE_COLUMNS = ["src_ip", "dst_ip", "proto", "sport", "dport", "packet_count",
                "byte_count", "anomaly_score", "severity", "label", "timestamp"]
SWEEP_EVERY = 1.0  # seconds between checks for idle flows


class LiveScorer:
    def __init__(self, model, scaler, out_path, failed_logins=None, quiet=False):
        self.model = model
        self.scaler = scaler
        self.out_path = out_path
        self.failed_logins = failed_logins or {}
        self.quiet = quiet
        self.table = FlowTable()
        self.last_sweep = 0.0
        self.scored = 0
        self.flagged = 0
        paths.ensure(out_path.parent)
        if not out_path.exists() or out_path.stat().st_size == 0:
            with open(out_path, "w", newline="") as f:
                csv.writer(f).writerow(LIVE_COLUMNS)

    def add(self, key, ts, size, tcp_flags=0):
        done = self.table.add(key, ts, size, tcp_flags)
        if ts - self.last_sweep >= SWEEP_EVERY:
            done += self.table.sweep(ts)
            self.last_sweep = ts
        for flow in done:
            self.score(flow)

    def flush(self):
        for flow in self.table.flush():
            self.score(flow)

    def score(self, flow):
        feats = flow_features(flow, self.failed_logins.get(flow.key[0], 0))
        X = pd.DataFrame([[feats[c] for c in FEATURE_ORDER]], columns=FEATURE_ORDER)
        Z = self.scaler.transform(X)
        s = float(self.model.decision_function(Z)[0])
        label = "anomaly" if s < 0 else "normal"
        sev = severity(s)
        self.scored += 1
        self.flagged += label == "anomaly"
        with open(self.out_path, "a", newline="") as f:
            csv.writer(f).writerow([feats["src_ip"], feats["dst_ip"], feats["proto"],
                                    feats["sport"], feats["dport"], feats["packet_count"],
                                    feats["byte_count"], round(s, 5), sev, label, time.time()])
        if not self.quiet and (label == "anomaly"):
            print(f"[live] {sev:<8} {s:.3f}  {feats['src_ip']}:{feats['sport']} -> "
                  f"{feats['dst_ip']}:{feats['dport']}  ({feats['packet_count']} packets)")


def _packet_fields(pkt):
    """Pull (key, ts, size, flags) out of a Scapy packet, or None for non-IP."""
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    if IP in pkt:
        ip, proto = pkt[IP], pkt[IP].proto
    elif IPv6 in pkt:
        ip, proto = pkt[IPv6], pkt[IPv6].nh
    else:
        return None
    sport = dport = flags = 0
    if TCP in pkt:
        sport, dport, flags = pkt[TCP].sport, pkt[TCP].dport, int(pkt[TCP].flags)
    elif UDP in pkt:
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    return (ip.src, ip.dst, proto, sport, dport), float(pkt.time), len(pkt), flags


def _failed_logins_by_ip():
    try:
        summary = pd.read_csv(paths.ip_log_summary_csv())
        return dict(zip(summary["src_ip"], summary["failed_logins_from_ip"]))
    except (OSError, KeyError, ValueError):
        return {}


def start_live_capture(interface: str = "en0", bpf_filter: str = None):
    try:
        from scapy.all import sniff
    except ImportError:
        raise SystemExit("[live] Scapy isn't installed. Run: pip install scapy")
    try:
        model, scaler = load()
    except (OSError, ValueError) as e:
        raise SystemExit(f"[live] No usable model ({e}). Run `anomaly-detect run` first to train one.")

    scorer = LiveScorer(model, scaler, paths.live_predictions_csv(), _failed_logins_by_ip())

    def handle(pkt):
        fields = _packet_fields(pkt)
        if fields:
            scorer.add(*fields)

    print(f"[live] Capturing on {interface}. Flagged flows print here; all flows go to "
          f"{paths.live_predictions_csv()}")
    print("[live] Press Ctrl+C to stop.\n")
    try:
        sniff(iface=interface, prn=handle, store=False, filter=bpf_filter)
    except PermissionError:
        raise SystemExit("[live] Permission denied. Packet capture needs sudo: "
                         "sudo anomaly-detect live --iface " + interface)
    except KeyboardInterrupt:
        pass
    finally:
        scorer.flush()
        print(f"\n[live] Stopped. Scored {scorer.scored} flows, flagged {scorer.flagged}.")
