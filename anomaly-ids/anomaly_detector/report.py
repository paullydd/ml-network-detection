"""Stage 5: write an HTML report of the flagged flows."""
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import paths
from .features import SEVERITY_BANDS

TEMPLATES = Path(__file__).parent / "templates"
PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}


def _fmt_time(ts) -> str:
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError, OSError):
        return ""


def render(pred: pd.DataFrame, top_n: int = 25) -> str:
    anomalies = pred[pred["label"] == "anomaly"].sort_values("anomaly_score")
    severities = ["Critical", "High", "Medium", "Low"]
    sev_counts = {s: int((anomalies["severity"] == s).sum()) for s in severities}

    rows = []
    for _, r in anomalies.head(top_n).iterrows():
        rows.append({
            "severity": r.severity,
            "score": f"{r.anomaly_score:.3f}",
            "src": f"{r.src_ip}:{int(r.sport)}",
            "dst": f"{r.dst_ip}:{int(r.dport)}",
            "proto": PROTO_NAMES.get(int(r.proto), str(int(r.proto))),
            "packets": int(r.packet_count),
            "bytes": int(r.byte_count),
            "duration": f"{r.flow_duration:.1f}s",
            "failed_logins": int(r.failed_logins_from_ip),
            "why": r.get("top_factors", "") if isinstance(r.get("top_factors", ""), str) else "",
            "start": _fmt_time(r.start_time),
        })

    by_src = (anomalies.groupby("src_ip").size().sort_values(ascending=False).head(10)
              .reset_index(name="count").to_dict("records"))

    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html"]))
    return env.get_template("report.html").render(
        generated=datetime.now().strftime("%Y-%m-%d %H:%M"),
        total=len(pred),
        n_anomalies=len(anomalies),
        rate=(len(anomalies) / len(pred) * 100) if len(pred) else 0,
        sev_counts=sev_counts,
        bands=SEVERITY_BANDS,
        rows=rows,
        top_n=min(top_n, len(anomalies)),
        by_src=by_src,
    )


def run() -> Path:
    if not paths.predictions_csv().exists():
        raise SystemExit("[report] No predictions yet. Run `anomaly-detect predict` first.")
    pred = pd.read_csv(paths.predictions_csv(), keep_default_na=False,
                       dtype={"top_factors": str})
    paths.ensure(paths.reports())
    paths.report_html().write_text(render(pred), encoding="utf-8")
    print(f"[report] Saved {paths.report_html()}")
    return paths.report_html()
