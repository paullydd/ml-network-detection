"""Where the project keeps its data, models and reports.

The project home is, in order of preference:
  1. the ANOMALY_IDS_HOME environment variable (or `anomaly-detect --home`)
  2. the anomaly-ids folder this package lives in (editable install / source checkout)
  3. the current working directory
"""
import os
from pathlib import Path

_PACKAGE_PARENT = Path(__file__).resolve().parent.parent


def home() -> Path:
    env = os.environ.get("ANOMALY_IDS_HOME")
    if env:
        return Path(env).expanduser().resolve()
    if (_PACKAGE_PARENT / "setup.py").exists():
        return _PACKAGE_PARENT
    return Path.cwd()


def raw_logs() -> Path:
    return home() / "data" / "raw" / "logs"


def raw_pcaps() -> Path:
    return home() / "data" / "raw" / "pcaps"


def processed() -> Path:
    return home() / "data" / "processed"


def live() -> Path:
    return home() / "data" / "live"


def models() -> Path:
    return home() / "model_outputs"


def reports() -> Path:
    return home() / "reports"


# Files passed between pipeline stages
def logs_pkl() -> Path:
    return processed() / "logs.pkl"


def ip_log_summary_csv() -> Path:
    return processed() / "ip_log_summary.csv"


def pcap_features_csv() -> Path:
    return processed() / "pcap_features.csv"


def features_csv() -> Path:
    return processed() / "features.csv"


def predictions_csv() -> Path:
    return processed() / "predictions.csv"


def model_pkl() -> Path:
    return models() / "iforest.pkl"


def scaler_pkl() -> Path:
    return models() / "scaler.pkl"


def live_predictions_csv() -> Path:
    return live() / "live_predictions.csv"


def report_html() -> Path:
    return reports() / "anomaly_report.html"


def ensure(*dirs: Path) -> None:
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
