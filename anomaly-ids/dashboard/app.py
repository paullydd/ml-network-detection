"""Batch dashboard: review the flows scored by `anomaly-detect run`.

Start it with `anomaly-detect dashboard` (or `streamlit run dashboard/app.py`).
"""
import sys
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from anomaly_detector import paths  # noqa: E402

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
SEVERITY_COLORS = ["#c0392b", "#e67e22", "#d4ac0d", "#2d6a4f"]

st.set_page_config(page_title="Network Anomaly Detection", layout="wide")
st.title("Network anomaly detection")
st.caption("Flows from your PCAPs, joined with Windows logon activity and scored by an Isolation Forest.")

pred_path = paths.predictions_csv()
if not pred_path.exists():
    st.error(f"No predictions at {pred_path}. Run `anomaly-detect run` first.")
    st.stop()

df = pd.read_csv(pred_path, keep_default_na=False)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Flows", len(df))
c2.metric("Normal", int((df["label"] == "normal").sum()))
c3.metric("Anomalies", int((df["label"] == "anomaly").sum()))
c4.metric("Critical", int((df["severity"] == "Critical").sum()))

st.subheader("Anomaly score distribution")
st.caption("Lower scores are more unusual.")
st.altair_chart(
    alt.Chart(df).mark_bar().encode(
        x=alt.X("anomaly_score:Q", bin=alt.Bin(maxbins=40), title="Anomaly score"),
        y=alt.Y("count()", title="Flows"),
        color=alt.Color("label:N", title="Label"),
    ).properties(height=280),
    use_container_width=True,
)

st.subheader("Flow explorer")
lo, hi = float(df["anomaly_score"].min()), float(df["anomaly_score"].max())
f1, f2, f3 = st.columns([2, 1, 1])
score_range = f1.slider("Anomaly score", lo, hi, (lo, hi)) if lo < hi else (lo, hi)
labels = f2.multiselect("Label", sorted(df["label"].unique()), default=sorted(df["label"].unique()))
sevs = f3.multiselect("Severity", SEVERITY_ORDER, default=SEVERITY_ORDER)
ip_query = st.text_input("Filter by IP", placeholder="e.g. 192.168.1.22")

view = df[df["anomaly_score"].between(*score_range) & df["label"].isin(labels) & df["severity"].isin(sevs)]
if ip_query:
    view = view[view["src_ip"].str.contains(ip_query, regex=False) |
                view["dst_ip"].str.contains(ip_query, regex=False)]

cols = ["severity", "anomaly_score", "src_ip", "sport", "dst_ip", "dport", "proto",
        "packet_count", "byte_count", "flow_duration", "failed_logins_from_ip", "top_factors", "label"]
st.dataframe(view[[c for c in cols if c in view.columns]], height=420, use_container_width=True)

st.subheader("Flagged flows by source")
flagged = df[df["label"] == "anomaly"]
if flagged.empty:
    st.info("No flows were flagged.")
else:
    st.altair_chart(
        alt.Chart(flagged).mark_bar().encode(
            y=alt.Y("src_ip:N", sort="-x", title="Source IP"),
            x=alt.X("count()", title="Flagged flows"),
            color=alt.Color("severity:N", scale=alt.Scale(domain=SEVERITY_ORDER, range=SEVERITY_COLORS)),
        ).properties(height=min(40 * flagged["src_ip"].nunique() + 40, 400)),
        use_container_width=True,
    )
