"""Flow building and the model's feature set.

Batch (PCAP) mode and live mode both use FlowTable and flow_features, so a flow
is described exactly the same way at training time and at scoring time.
"""
from dataclasses import dataclass, field
import ipaddress

# The model and scaler are trained on these columns, in this order.
FEATURE_ORDER = [
    "proto",
    "sport",
    "dport",
    "packet_count",
    "byte_count",
    "flow_duration",
    "avg_interarrival",
    "syn_count",
    "ack_count",
    "ip",                     # 1 if the source address is private/internal
    "failed_logins_from_ip",  # from Windows 4625 events for the source IP
]

ID_COLUMNS = ["src_ip", "dst_ip", "start_time", "end_time"]

# A flow ends after this many seconds with no packets.
FLOW_TIMEOUT = 5.0

TCP_SYN = 0x02
TCP_ACK = 0x10

# Severity cut-offs for the anomaly score (the Isolation Forest decision
# function). Below 0 the flow is flagged; the further below, the more severe.
SEVERITY_BANDS = [(-0.2, "Critical"), (-0.1, "High"), (-0.05, "Medium")]


def severity(score: float) -> str:
    for cutoff, name in SEVERITY_BANDS:
        if score < cutoff:
            return name
    return "Low"


INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC 1918
    "127.0.0.0/8", "169.254.0.0/16",                   # loopback, link-local
    "::1/128", "fc00::/7", "fe80::/10",                 # IPv6 loopback, ULA, link-local
)]


def is_internal(ip: str) -> int:
    """1 if the address is on a private/local network, else 0."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return 0
    return int(any(addr in net for net in INTERNAL_NETWORKS if net.version == addr.version))


@dataclass
class Flow:
    key: tuple                     # (src_ip, dst_ip, proto, sport, dport)
    times: list = field(default_factory=list)
    sizes: list = field(default_factory=list)
    syn: int = 0
    ack: int = 0

    @property
    def last_seen(self) -> float:
        return self.times[-1]


class FlowTable:
    """Groups packets into one-directional flows keyed by 5-tuple.

    A flow is finished when it has been idle for `timeout` seconds of packet
    time, so batch and live mode split traffic the same way.
    """

    def __init__(self, timeout: float = FLOW_TIMEOUT):
        self.timeout = timeout
        self.flows = {}

    def add(self, key, ts: float, size: int, tcp_flags: int = 0) -> list:
        """Add a packet. Returns any flow with this key that it closes."""
        finished = []
        flow = self.flows.get(key)
        if flow is not None and ts - flow.last_seen > self.timeout:
            finished.append(self.flows.pop(key))
            flow = None
        if flow is None:
            flow = self.flows[key] = Flow(key)
        flow.times.append(ts)
        flow.sizes.append(size)
        if tcp_flags & TCP_SYN:
            flow.syn += 1
        if tcp_flags & TCP_ACK:
            flow.ack += 1
        return finished

    def sweep(self, now: float) -> list:
        """Close and return every flow idle for longer than the timeout."""
        done = [k for k, f in self.flows.items() if now - f.last_seen > self.timeout]
        return [self.flows.pop(k) for k in done]

    def flush(self) -> list:
        """Close and return every open flow."""
        done = list(self.flows.values())
        self.flows.clear()
        return done


def flow_features(flow: Flow, failed_logins_from_ip: int = 0) -> dict:
    """Describe a finished flow as identity columns plus the model features."""
    src, dst, proto, sport, dport = flow.key
    times = sorted(flow.times)
    n = len(times)
    duration = times[-1] - times[0] if n > 1 else 0.0
    return {
        "src_ip": src,
        "dst_ip": dst,
        "start_time": times[0],
        "end_time": times[-1],
        "proto": int(proto),
        "sport": int(sport),
        "dport": int(dport),
        "packet_count": n,
        "byte_count": int(sum(flow.sizes)),
        "flow_duration": float(duration),
        "avg_interarrival": float(duration / (n - 1)) if n > 1 else 0.0,
        "syn_count": flow.syn,
        "ack_count": flow.ack,
        "ip": is_internal(src),
        "failed_logins_from_ip": int(failed_logins_from_ip),
    }
