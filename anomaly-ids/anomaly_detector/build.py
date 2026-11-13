"""Stage 3: join log activity onto network flows to make the model's dataset."""
import pandas as pd

from . import paths
from .features import FEATURE_ORDER


def build(flows: pd.DataFrame, ip_summary: pd.DataFrame) -> pd.DataFrame:
    df = flows.copy()
    if "failed_logins_from_ip" in df.columns:
        df = df.drop(columns="failed_logins_from_ip")
    if ip_summary is not None and not ip_summary.empty:
        df = df.merge(ip_summary[["src_ip", "failed_logins_from_ip"]], on="src_ip", how="left")
    else:
        df["failed_logins_from_ip"] = 0
    df["failed_logins_from_ip"] = df["failed_logins_from_ip"].fillna(0).astype(int)
    for col in FEATURE_ORDER:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
    return df


def run() -> pd.DataFrame:
    if not paths.pcap_features_csv().exists():
        raise SystemExit("[features] No flow features yet. Run `anomaly-detect pcap` first.")
    flows = pd.read_csv(paths.pcap_features_csv())
    summary = (pd.read_csv(paths.ip_log_summary_csv())
               if paths.ip_log_summary_csv().exists() else None)
    if summary is None:
        print("[features] No log summary found. Run `anomaly-detect logs` to include login data.")
    df = build(flows, summary)
    df.to_csv(paths.features_csv(), index=False)
    linked = int((df["failed_logins_from_ip"] > 0).sum())
    print(f"[features] {len(df)} flows, {linked} from IPs with failed logons. "
          f"Saved {paths.features_csv()}")
    return df
