"""Stage 1: load Windows Security event logs exported as CSV.

Keeps the events the detector uses:
  4624  successful logon
  4625  failed logon
  4688  process creation
and summarizes them per source IP so they can be joined onto network flows.
"""
from pathlib import Path

import pandas as pd

from . import paths

EVENTS = {4624: "logon_success", 4625: "logon_failure", 4688: "process_creation"}
COLUMNS = ["EventID", "AccountName", "ProcessName", "LogonType", "TimeCreated",
           "MachineName", "Status", "IPAddress"]


def load_logs(files) -> pd.DataFrame:
    frames = []
    for f in files:
        df = pd.read_csv(f, dtype=str, skip_blank_lines=True)
        df.columns = [c.strip() for c in df.columns]
        missing = {"EventID", "TimeCreated"} - set(df.columns)
        if missing:
            raise ValueError(f"{Path(f).name} is missing columns: {', '.join(sorted(missing))}")
        for col in COLUMNS:
            if col not in df.columns:
                df[col] = None
        df = df[COLUMNS].copy()
        df["source_file"] = Path(f).name
        frames.append(df)
    if not frames:
        return pd.DataFrame(columns=COLUMNS + ["source_file", "event"])

    logs = pd.concat(frames, ignore_index=True)
    logs = logs.dropna(subset=["EventID"])
    logs["EventID"] = pd.to_numeric(logs["EventID"], errors="coerce")
    logs = logs[logs["EventID"].isin(EVENTS)].copy()
    logs["EventID"] = logs["EventID"].astype(int)
    logs["event"] = logs["EventID"].map(EVENTS)
    logs["TimeCreated"] = pd.to_datetime(logs["TimeCreated"], errors="coerce")
    for col in ("AccountName", "ProcessName", "IPAddress", "MachineName", "Status"):
        logs[col] = logs[col].fillna("").str.strip()
    return logs.sort_values("TimeCreated").reset_index(drop=True)


def summarize_by_ip(logs: pd.DataFrame) -> pd.DataFrame:
    """One row per source IP with its login activity."""
    cols = ["src_ip", "failed_logins_from_ip", "successful_logins_from_ip", "accounts_targeted"]
    with_ip = logs[logs["IPAddress"] != ""]
    if with_ip.empty:
        return pd.DataFrame(columns=cols)
    failed = with_ip[with_ip["EventID"] == 4625]
    success = with_ip[with_ip["EventID"] == 4624]
    summary = pd.DataFrame({
        "failed_logins_from_ip": failed.groupby("IPAddress").size(),
        "successful_logins_from_ip": success.groupby("IPAddress").size(),
        "accounts_targeted": failed.groupby("IPAddress")["AccountName"].nunique(),
    }).fillna(0).astype(int)
    summary.index.name = "src_ip"
    return summary.reset_index()[cols]


def run(log_dir: Path = None) -> pd.DataFrame:
    log_dir = Path(log_dir or paths.raw_logs())
    files = sorted(log_dir.glob("*.csv"))
    if not files:
        print(f"[logs] No CSV logs in {log_dir}. Flows will get 0 failed logins.")
    logs = load_logs(files)
    summary = summarize_by_ip(logs)

    paths.ensure(paths.processed())
    logs.to_pickle(paths.logs_pkl())
    summary.to_csv(paths.ip_log_summary_csv(), index=False)

    counts = logs["event"].value_counts()
    print(f"[logs] {len(files)} file(s), {len(logs)} events: "
          f"{counts.get('logon_failure', 0)} failed logons, "
          f"{counts.get('logon_success', 0)} successful logons, "
          f"{counts.get('process_creation', 0)} process creations")
    for _, row in summary.sort_values("failed_logins_from_ip", ascending=False).head(5).iterrows():
        if row.failed_logins_from_ip:
            print(f"[logs]   {row.src_ip}: {row.failed_logins_from_ip} failed logons "
                  f"across {row.accounts_targeted} account(s)")
    print(f"[logs] Saved {paths.logs_pkl()}")
    return logs
