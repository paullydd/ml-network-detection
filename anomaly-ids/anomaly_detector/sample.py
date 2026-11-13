"""Generate data/raw/pcaps/sample_traffic.pcap (run `anomaly-detect sample`): synthetic office traffic with an
attack hidden in it, lined up with data/raw/logs/sample_security_logs.csv.

Background (09:30-12:00 UTC, 2025-02-01): DNS lookups, HTTPS browsing and SMB
file-share traffic from about 17 workstations.

Attack from 192.168.1.22, matching the logon events in the sample logs:
  09:58  SYN scan of 50 ports on the file server 192.168.1.5
  10:00  8 rapid RDP connection attempts to 192.168.1.10 (the 4625 burst for jdoe)
  10:06  RDP session after the successful logon (4624)
  10:08  large outbound HTTPS upload to 203.0.113.50 (exfiltration)
Plus 5 quick SMB attempts from 192.168.1.34 at 11:15 (the jsmith failures).
"""
import random
from datetime import datetime, timezone
from pathlib import Path

from . import paths
from .pcap_reader import PROTO_TCP, PROTO_UDP, PcapWriter

SYN, ACK, PSH, FIN, RST = 0x02, 0x10, 0x08, 0x01, 0x04
DAY = datetime(2025, 2, 1, tzinfo=timezone.utc).timestamp()
GATEWAY, FILESERVER = "192.168.1.1", "192.168.1.5"
WEB = ["142.250.72.14", "151.101.1.69", "104.16.132.229", "13.107.42.14", "52.84.150.11",
       "172.217.3.110", "23.215.0.136", "185.199.108.153"]
WORKSTATIONS = [f"192.168.1.{n}" for n in range(10, 60, 3)]


def at(h, m, s=0.0):
    return DAY + h * 3600 + m * 60 + s


def tcp_session(pkts, t, client, server, sport, dport, n_data, up_size, down_size, gap):
    """A full TCP conversation: handshake, data both ways, close."""
    pkts.append((t, client, server, PROTO_TCP, sport, dport, SYN, 0))
    pkts.append((t + 0.02, server, client, PROTO_TCP, dport, sport, SYN | ACK, 0))
    pkts.append((t + 0.03, client, server, PROTO_TCP, sport, dport, ACK, 0))
    t += 0.05
    for _ in range(n_data):
        pkts.append((t, client, server, PROTO_TCP, sport, dport, PSH | ACK, up_size))
        pkts.append((t + 0.01, server, client, PROTO_TCP, dport, sport, PSH | ACK, down_size))
        t += gap * random.uniform(0.5, 1.5)
    pkts.append((t, client, server, PROTO_TCP, sport, dport, FIN | ACK, 0))
    pkts.append((t + 0.02, server, client, PROTO_TCP, dport, sport, FIN | ACK, 0))
    return t


def background(pkts):
    for host in WORKSTATIONS:
        t = at(9, 30, random.uniform(0, 300))
        while t < at(12, 0):
            kind = random.random()
            sport = random.randint(49152, 65000)
            if kind < 0.45:  # DNS lookup
                pkts.append((t, host, GATEWAY, PROTO_UDP, sport, 53, 0, random.randint(30, 60)))
                pkts.append((t + 0.01, GATEWAY, host, PROTO_UDP, 53, sport, 0, random.randint(60, 200)))
            elif kind < 0.9:  # HTTPS browsing
                tcp_session(pkts, t, host, random.choice(WEB), sport, 443,
                            n_data=random.randint(4, 25), up_size=random.randint(80, 600),
                            down_size=random.randint(600, 1400), gap=random.uniform(0.05, 0.4))
            else:  # SMB file share
                tcp_session(pkts, t, host, FILESERVER, sport, 445,
                            n_data=random.randint(8, 40), up_size=random.randint(100, 400),
                            down_size=random.randint(400, 1400), gap=random.uniform(0.02, 0.1))
            t += random.expovariate(1 / 420)  # a new connection every ~4 minutes per host


def attack(pkts):
    attacker = "192.168.1.22"
    # Port scan: one SYN per port, closed ports answer with RST
    t = at(9, 58)
    for port in random.sample(range(1, 1024), 50):
        sport = random.randint(40000, 60000)
        pkts.append((t, attacker, FILESERVER, PROTO_TCP, sport, port, SYN, 0))
        pkts.append((t + 0.001, FILESERVER, attacker, PROTO_TCP, port, sport, RST | ACK, 0))
        t += 0.02
    # RDP brute force: 8 short connections, 2 seconds apart (matches the 4625 burst)
    for i in range(8):
        tcp_session(pkts, at(10, 0, 1 + 2 * i), attacker, "192.168.1.10", 51000 + i, 3389,
                    n_data=4, up_size=300, down_size=900, gap=0.05)
    # RDP session after the successful logon
    tcp_session(pkts, at(10, 6, 11), attacker, "192.168.1.10", 51100, 3389,
                n_data=150, up_size=200, down_size=1300, gap=0.3)
    # Exfiltration: big upload to an unfamiliar external host
    tcp_session(pkts, at(10, 8, 0), attacker, "203.0.113.50", 51200, 443,
                n_data=900, up_size=1400, down_size=60, gap=0.06)
    # jsmith failures from 192.168.1.34: 5 quick SMB logon attempts
    for i in range(5):
        tcp_session(pkts, at(11, 15, 50 + 2 * i), "192.168.1.34", FILESERVER, 52000 + i, 445,
                    n_data=3, up_size=250, down_size=150, gap=0.05)


def generate(out=None, seed: int = 7) -> Path:
    random.seed(seed)
    pkts = []
    background(pkts)
    attack(pkts)
    pkts.sort(key=lambda p: p[0])
    out = Path(out or paths.raw_pcaps() / "sample_traffic.pcap")
    out.parent.mkdir(parents=True, exist_ok=True)
    with PcapWriter(out) as w:
        for ts, src, dst, proto, sport, dport, flags, payload in pkts:
            w.write(ts, src, dst, proto, sport, dport, flags, payload)
    print(f"[sample] Wrote {len(pkts)} packets to {out}")
    return out
