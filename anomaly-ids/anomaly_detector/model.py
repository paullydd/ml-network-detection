"""Stage 4: train the Isolation Forest and score every flow.

Isolation Forest is unsupervised: it learns what most flows look like and gives
each flow a score. The score is the model's decision function: below 0 means
the flow is flagged as an anomaly, and the more negative, the more unusual.
The model flags roughly `contamination` of the training flows.
"""
import pickle
import warnings

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from . import paths
from .features import FEATURE_ORDER, severity

CONTAMINATION = 0.05
N_ESTIMATORS = 200
RANDOM_STATE = 42

FEATURE_LABELS = {
    "proto": "protocol",
    "sport": "source port",
    "dport": "destination port",
    "packet_count": "packet count",
    "byte_count": "bytes sent",
    "flow_duration": "duration",
    "avg_interarrival": "time between packets",
    "syn_count": "SYN packets",
    "ack_count": "ACK packets",
    "ip": "internal source",
    "failed_logins_from_ip": "failed logons from this IP",
}


def train(X: pd.DataFrame, contamination: float = CONTAMINATION):
    scaler = StandardScaler().fit(X)
    model = IsolationForest(n_estimators=N_ESTIMATORS, contamination=contamination,
                            random_state=RANDOM_STATE)
    model.fit(scaler.transform(X))
    return model, scaler


def save(model, scaler) -> None:
    paths.ensure(paths.models())
    with open(paths.model_pkl(), "wb") as f:
        pickle.dump(model, f)
    with open(paths.scaler_pkl(), "wb") as f:
        pickle.dump(scaler, f)


def load():
    with open(paths.model_pkl(), "rb") as f:
        model = pickle.load(f)
    with open(paths.scaler_pkl(), "rb") as f:
        scaler = pickle.load(f)
    n = getattr(scaler, "n_features_in_", len(FEATURE_ORDER))
    if n != len(FEATURE_ORDER):
        raise ValueError(f"saved scaler expects {n} features, this version uses {len(FEATURE_ORDER)}")
    return model, scaler


def top_factors(z_row: np.ndarray, k: int = 2) -> str:
    """The features furthest from normal for one flow, in plain words."""
    order = np.argsort(-np.abs(z_row))[:k]
    parts = []
    for i in order:
        if abs(z_row[i]) < 1.5:
            continue
        name = FEATURE_ORDER[i]
        if name == "ip":
            parts.append("internal source" if z_row[i] > 0 else "external source")
        else:
            direction = "high" if z_row[i] > 0 else "low"
            parts.append(f"{FEATURE_LABELS[name]} unusually {direction}")
    return "; ".join(parts)


def score(df: pd.DataFrame, model, scaler) -> pd.DataFrame:
    X = df[FEATURE_ORDER].astype(float)
    Z = scaler.transform(X)
    out = df.copy()
    out["anomaly_score"] = model.decision_function(Z)
    out["label"] = np.where(out["anomaly_score"] < 0, "anomaly", "normal")
    out["severity"] = out["anomaly_score"].apply(severity)
    out["top_factors"] = [top_factors(z) if lbl == "anomaly" else ""
                          for z, lbl in zip(Z, out["label"])]
    return out.sort_values("anomaly_score").reset_index(drop=True)


def run(retrain: bool = True, contamination: float = CONTAMINATION) -> pd.DataFrame:
    if not paths.features_csv().exists():
        raise SystemExit("[predict] No feature dataset yet. Run `anomaly-detect features` first.")
    df = pd.read_csv(paths.features_csv())
    if df.empty:
        raise SystemExit("[predict] The feature dataset is empty.")

    if retrain:
        model, scaler = train(df[FEATURE_ORDER].astype(float), contamination)
        save(model, scaler)
        print(f"[predict] Trained Isolation Forest on {len(df)} flows "
              f"(contamination {contamination}). Saved {paths.model_pkl()}")
    else:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                model, scaler = load()
        except (OSError, ValueError, pickle.UnpicklingError) as e:
            raise SystemExit(f"[predict] Couldn't load the saved model ({e}). "
                             "Run `anomaly-detect predict` without --use-saved to train one.")
        print(f"[predict] Scoring {len(df)} flows with the saved model")

    out = score(df, model, scaler)
    out.to_csv(paths.predictions_csv(), index=False)
    n_anom = int((out["label"] == "anomaly").sum())
    print(f"[predict] {n_anom} of {len(out)} flows flagged as anomalies. "
          f"Saved {paths.predictions_csv()}")
    for _, r in out[out["label"] == "anomaly"].head(5).iterrows():
        why = f"  ({r.top_factors})" if r.top_factors else ""
        print(f"[predict]   {r.severity:<8} {r.anomaly_score:.3f}  "
              f"{r.src_ip}:{int(r.sport)} -> {r.dst_ip}:{int(r.dport)}{why}")
    return out
