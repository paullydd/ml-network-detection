import shutil
import struct
from pathlib import Path

import pandas as pd
import pytest
from click.testing import CliRunner

from anomaly_detector import build, logs, model, paths
from anomaly_detector.cli import cli
from anomaly_detector.features import FEATURE_ORDER, FlowTable, flow_features, is_internal, severity
from anomaly_detector.live_capture import LiveScorer
from anomaly_detector.pcap import flows_from_pcap
from anomaly_detector.pcap_reader import PROTO_TCP, PROTO_UDP, PcapError, PcapWriter, read_packets

ROOT = Path(__file__).resolve().parent.parent
SAMPLE_LOGS = ROOT / "data" / "raw" / "logs" / "sample_security_logs.csv"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("ANOMALY_IDS_HOME", str(tmp_path))
    (tmp_path / "data" / "raw" / "logs").mkdir(parents=True)
    (tmp_path / "data" / "raw" / "pcaps").mkdir(parents=True)
    shutil.copy(SAMPLE_LOGS, tmp_path / "data" / "raw" / "logs")
    return tmp_path


# ------------------------------------------------------------- pcap reading

def test_pcap_round_trip(tmp_path):
    f = tmp_path / "t.pcap"
    with PcapWriter(f) as w:
        w.write(100.25, "10.0.0.1", "8.8.8.8", PROTO_UDP, 5000, 53, payload_len=20)
        w.write(101.5, "10.0.0.1", "1.1.1.1", PROTO_TCP, 6000, 443, tcp_flags=0x02)
    pkts = list(read_packets(f))
    assert [p.key for p in pkts] == [("10.0.0.1", "8.8.8.8", 17, 5000, 53),
                                     ("10.0.0.1", "1.1.1.1", 6, 6000, 443)]
    assert pkts[0].ts == pytest.approx(100.25)
    assert pkts[0].size == 14 + 20 + 8 + 20
    assert pkts[1].tcp_flags == 0x02


def _pcapng_bytes(frame: bytes, ts_us: int) -> bytes:
    def block(btype, body):
        pad = b"\x00" * (-len(body) % 4)
        n = 12 + len(body) + len(pad)
        return struct.pack("<II", btype, n) + body + pad + struct.pack("<I", n)

    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(1, struct.pack("<HHI", 1, 0, 65535))
    epb = block(6, struct.pack("<IIIII", 0, ts_us >> 32, ts_us & 0xFFFFFFFF, len(frame), len(frame)) + frame)
    return shb + idb + epb


def test_pcapng(tmp_path):
    src = tmp_path / "one.pcap"
    with PcapWriter(src) as w:
        w.write(5.0, "192.168.1.9", "10.1.1.1", PROTO_TCP, 1234, 22, tcp_flags=0x12)
    frame = src.read_bytes()[24 + 16:]  # skip pcap file + record headers
    ng = tmp_path / "one.pcapng"
    ng.write_bytes(_pcapng_bytes(frame, 1_700_000_000_500_000))
    (pkt,) = list(read_packets(ng))
    assert pkt.key == ("192.168.1.9", "10.1.1.1", 6, 1234, 22)
    assert pkt.ts == pytest.approx(1_700_000_000.5)
    assert pkt.tcp_flags == 0x12


def test_rejects_non_pcap(tmp_path):
    bad = tmp_path / "notes.pcap"
    bad.write_text("hello")
    with pytest.raises(PcapError):
        list(read_packets(bad))


# ------------------------------------------------------------- flows

def test_flow_table_splits_on_idle_timeout():
    t = FlowTable(timeout=5)
    key = ("10.0.0.1", "10.0.0.2", 6, 1000, 80)
    assert t.add(key, 0.0, 60, 0x02) == []
    assert t.add(key, 1.0, 100, 0x10) == []
    closed = t.add(key, 10.0, 60)  # 9s gap ends the first flow
    assert len(closed) == 1
    f = flow_features(closed[0], failed_logins_from_ip=3)
    assert f["packet_count"] == 2 and f["byte_count"] == 160
    assert f["flow_duration"] == 1.0 and f["avg_interarrival"] == 1.0
    assert f["syn_count"] == 1 and f["ack_count"] == 1
    assert f["ip"] == 1 and f["failed_logins_from_ip"] == 3
    assert len(t.flush()) == 1


def _one_packet_flow():
    t = FlowTable()
    t.add(("8.8.8.8", "10.0.0.1", 17, 53, 5000), 0.0, 90)
    return t.flush()[0]


def test_flow_features_cover_the_model_features():
    assert set(FEATURE_ORDER) <= set(flow_features(_one_packet_flow()))


def test_is_internal_and_severity():
    assert is_internal("192.168.1.22") and is_internal("10.2.3.4") and is_internal("fe80::1")
    assert is_internal("172.20.0.5")
    assert not is_internal("8.8.8.8") and not is_internal("203.0.113.50") and not is_internal("not-an-ip")
    assert severity(-0.3) == "Critical" and severity(-0.15) == "High"
    assert severity(-0.07) == "Medium" and severity(0.1) == "Low"


# ------------------------------------------------------------- logs

def test_log_summary_counts_failed_logons_per_ip():
    events = logs.load_logs([SAMPLE_LOGS])
    assert (events["EventID"] == 4625).sum() == 13
    s = logs.summarize_by_ip(events).set_index("src_ip")
    assert s.loc["192.168.1.22", "failed_logins_from_ip"] == 8
    assert s.loc["192.168.1.34", "failed_logins_from_ip"] == 5
    assert s.loc["192.168.1.22", "successful_logins_from_ip"] == 1


def test_build_joins_logins_onto_flows():
    flows = pd.DataFrame([{**flow_features(_one_packet_flow()), "src_ip": "192.168.1.22"},
                          flow_features(_one_packet_flow())]).drop(columns="failed_logins_from_ip")
    summary = pd.DataFrame({"src_ip": ["192.168.1.22"], "failed_logins_from_ip": [8]})
    out = build.build(flows, summary)
    assert out["failed_logins_from_ip"].tolist() == [8, 0]


# ------------------------------------------------------------- end to end

def test_full_pipeline_on_sample_data(home):
    runner = CliRunner()
    assert runner.invoke(cli, ["sample"]).exit_code == 0
    result = runner.invoke(cli, ["run"])
    assert result.exit_code == 0, result.output

    pred = pd.read_csv(paths.predictions_csv(), keep_default_na=False)
    assert set(FEATURE_ORDER) <= set(pred.columns)
    assert {"anomaly_score", "label", "severity", "top_factors"} <= set(pred.columns)
    assert pred["label"].isin(["normal", "anomaly"]).all()

    # The exfiltration upload is the most unusual flow in the sample
    exfil = pred[(pred.src_ip == "192.168.1.22") & (pred.dst_ip == "203.0.113.50")]
    assert exfil["label"].iloc[0] == "anomaly"
    assert pred.iloc[0]["dst_ip"] == "203.0.113.50"

    html = paths.report_html().read_text()
    assert "Network anomaly report" in html and "203.0.113.50" in html

    # Saved model can score the same data again
    result = runner.invoke(cli, ["predict", "--use-saved"])
    assert result.exit_code == 0, result.output


def test_pcap_stage_explains_missing_captures(home):
    result = CliRunner().invoke(cli, ["pcap"])
    assert result.exit_code != 0
    assert "anomaly-detect sample" in result.output


def test_live_scorer_writes_scored_flows(home, tmp_path):
    X = pd.DataFrame([[6, 50000 + i, 443, 20, 8000, 2.0, 0.1, 1, 19, 1, 0] for i in range(50)],
                     columns=FEATURE_ORDER)
    m, s = model.train(X)
    out = tmp_path / "live.csv"
    scorer = LiveScorer(m, s, out, failed_logins={"10.0.0.9": 8}, quiet=True)
    key = ("10.0.0.9", "203.0.113.50", 6, 51200, 443)
    for i in range(300):
        scorer.add(key, 100 + i * 0.01, 1400, 0x18)
    scorer.add(("10.0.0.2", "1.1.1.1", 17, 5353, 53), 200.0, 80)  # sweeps the idle upload
    scorer.flush()
    rows = pd.read_csv(out)
    assert len(rows) == 2 and scorer.scored == 2
    upload = rows[rows.dst_ip == "203.0.113.50"].iloc[0]
    assert upload.packet_count == 300 and upload.label == "anomaly"
