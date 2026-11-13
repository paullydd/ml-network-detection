"""Runs the batch pipeline stages in order."""
from . import build, logs, model, pcap, report


def run_logs():
    return logs.run()


def run_pcap():
    return pcap.run()


def run_features():
    return build.run()


def run_predict(retrain: bool = True, contamination: float = model.CONTAMINATION):
    return model.run(retrain=retrain, contamination=contamination)


def run_report():
    return report.run()


def run_all(retrain: bool = True, contamination: float = model.CONTAMINATION):
    print("\n=== Network anomaly detection pipeline ===\n")
    run_logs()
    run_pcap()
    run_features()
    run_predict(retrain=retrain, contamination=contamination)
    path = run_report()
    print(f"\n=== Done. Open {path} ===\n")
    return path
