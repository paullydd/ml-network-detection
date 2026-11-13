import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import click

from . import model as model_mod
from . import paths, pipeline

retrain_option = click.option(
    "--use-saved", is_flag=True,
    help="Score with the saved model instead of training a new one on this data.")
contamination_option = click.option(
    "--contamination", default=model_mod.CONTAMINATION, show_default=True, type=float,
    help="Share of flows the model treats as anomalies when training.")


@click.group()
@click.option("--home", type=click.Path(file_okay=False), envvar="ANOMALY_IDS_HOME",
              help="Project folder with data/, model_outputs/ and reports/. "
                   "Defaults to the anomaly-ids folder.")
def cli(home):
    """Network anomaly detection: Windows logs + PCAP flows + Isolation Forest."""
    if home:
        os.environ["ANOMALY_IDS_HOME"] = str(Path(home).expanduser().resolve())


@cli.command()
@retrain_option
@contamination_option
def run(use_saved, contamination):
    """Run the full pipeline: logs, pcap, features, predict, report."""
    pipeline.run_all(retrain=not use_saved, contamination=contamination)


@cli.command()
def sample():
    """Generate a sample capture with a hidden attack in data/raw/pcaps."""
    from .sample import generate
    generate()


@cli.command()
def logs():
    """Load Windows Security logs from data/raw/logs."""
    pipeline.run_logs()


@cli.command()
def pcap():
    """Extract flow features from captures in data/raw/pcaps."""
    pipeline.run_pcap()


@cli.command()
def features():
    """Join login activity onto flows to build the model dataset."""
    pipeline.run_features()


@cli.command()
@retrain_option
@contamination_option
def predict(use_saved, contamination):
    """Train the model (or load the saved one) and score every flow."""
    pipeline.run_predict(retrain=not use_saved, contamination=contamination)


@cli.command()
def report():
    """Write the HTML anomaly report."""
    pipeline.run_report()


@cli.command()
@click.option("--iface", default="en0", show_default=True, help="Network interface to capture from.")
@click.option("--filter", "bpf_filter", default=None, help='BPF capture filter, e.g. "tcp or udp".')
def live(iface, bpf_filter):
    """Score live traffic with the saved model (needs sudo)."""
    from .live_capture import start_live_capture
    start_live_capture(interface=iface, bpf_filter=bpf_filter)


@cli.command()
@click.option("--live", "live_mode", is_flag=True, help="Open the live dashboard instead.")
def dashboard(live_mode):
    """Open the Streamlit dashboard."""
    app = paths.home() / "dashboard" / ("live_app.py" if live_mode else "app.py")
    if not app.exists():
        raise click.ClickException(f"Dashboard not found at {app}")
    if importlib.util.find_spec("streamlit") is None:
        raise click.ClickException("Streamlit isn't installed. Run: pip install -e '.[dashboard]'")
    env = dict(os.environ, ANOMALY_IDS_HOME=str(paths.home()))
    subprocess.run([sys.executable, "-m", "streamlit", "run", str(app)], env=env, check=False)


if __name__ == "__main__":
    cli()
