"""Stage 2: turn packet captures into network flows with features."""
from pathlib import Path

import pandas as pd

from . import paths
from .features import FEATURE_ORDER, FlowTable, flow_features
from .pcap_reader import PcapError, read_packets

PCAP_PATTERNS = ("*.pcap", "*.pcapng", "*.cap")


def flows_from_pcap(path) -> list:
    """Read one capture and return a feature dict for every flow in it."""
    table = FlowTable()
    finished = []
    last_sweep = None
    for pkt in read_packets(path):
        finished += table.add(pkt.key, pkt.ts, pkt.size, pkt.tcp_flags)
        if last_sweep is None or pkt.ts - last_sweep >= 1.0:
            finished += table.sweep(pkt.ts)
            last_sweep = pkt.ts
    finished += table.flush()
    rows = [flow_features(f) for f in finished]
    for r in rows:
        r["pcap_file"] = Path(path).name
    return rows


def run(pcap_dir: Path = None) -> pd.DataFrame:
    pcap_dir = Path(pcap_dir or paths.raw_pcaps())
    files = sorted({f for pat in PCAP_PATTERNS for f in pcap_dir.glob(pat)})
    if not files:
        raise SystemExit(f"[pcap] No .pcap or .pcapng files in {pcap_dir}. "
                         "Add a capture there (for example, save one from Wireshark), "
                         "or run `anomaly-detect sample` to generate a demo capture.")
    rows = []
    for f in files:
        try:
            got = flows_from_pcap(f)
        except PcapError as e:
            print(f"[pcap] Skipped {f.name}: {e}")
            continue
        print(f"[pcap] {f.name}: {len(got)} flows")
        rows += got

    cols = ["pcap_file", "src_ip", "dst_ip", "start_time", "end_time"] + \
           [c for c in FEATURE_ORDER if c != "failed_logins_from_ip"]
    df = pd.DataFrame(rows, columns=cols + ["failed_logins_from_ip"])[cols]
    df = df.sort_values("start_time").reset_index(drop=True)

    paths.ensure(paths.processed())
    df.to_csv(paths.pcap_features_csv(), index=False)
    print(f"[pcap] {len(df)} flows from {len(files)} capture(s). Saved {paths.pcap_features_csv()}")
    return df
