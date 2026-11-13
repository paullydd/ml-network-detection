"""Live dashboard: watch flows scored by `anomaly-detect live` as they arrive.

Start it with `anomaly-detect dashboard --live` while a live capture is running.
"""
import sys
import time
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from anomaly_detector import paths  # noqa: E402
from anomaly_detector.features import severity  # noqa: E402

REFRESH_SECONDS = 2

st.set_page_config(page_title="Live Network Anomaly Detection", layout="wide")
st.title("Live network anomaly detection")

paused = st.sidebar.toggle("Pause updates", value=False)
window = st.sidebar.slider("Show the most recent flows", 50, 2000, 500, step=50)

live_path = paths.live_predictions_csv()
if not live_path.exists() or live_path.stat().st_size == 0:
    st.info("Waiting for live data. Start a capture with: sudo anomaly-detect live --iface en0")
    df = None
else:
    df = pd.read_csv(live_path)

if df is not None and not df.empty:
    if "severity" not in df.columns:  # files written by older versions
        df["severity"] = df["anomaly_score"].apply(severity)
    df["time"] = pd.to_datetime(df["timestamp"], unit="s")
    df = df.sort_values("time").tail(window)

    c1, c2, c3 = st.columns(3)
    c1.metric("Flows shown", len(df))
    c2.metric("Anomalies", int((df["label"] == "anomaly").sum()))
    c3.metric("Critical", int((df["severity"] == "Critical").sum()))

    st.subheader("Anomaly score over time")
    st.altair_chart(
        alt.Chart(df).mark_circle(size=40).encode(
            x=alt.X("time:T", title="Time"),
            y=alt.Y("anomaly_score:Q", title="Anomaly score"),
            color=alt.Color("label:N", title="Label"),
            tooltip=["src_ip", "dst_ip", "dport", "anomaly_score", "severity"],
        ).properties(height=280),
        use_container_width=True,
    )

    st.subheader("Latest flows")
    cols = ["time", "severity", "anomaly_score", "src_ip", "sport", "dst_ip", "dport", "proto", "label"]
    st.dataframe(df.sort_values("time", ascending=False)[[c for c in cols if c in df.columns]],
                 height=420, use_container_width=True)

if not paused:
    time.sleep(REFRESH_SECONDS)
    st.rerun()
