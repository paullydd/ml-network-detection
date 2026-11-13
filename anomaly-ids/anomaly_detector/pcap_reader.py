"""A small, dependency-free reader for .pcap and .pcapng captures.

It pulls out only what flow building needs: timestamp, frame size, IP
addresses, protocol, ports and TCP flags. Supports IPv4 and IPv6 over Ethernet
(including VLAN tags), raw IP, BSD loopback and Linux cooked captures (SLL and
SLL2), which covers captures from Wireshark, tcpdump and tshark.
"""
import socket
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

# Link-layer types (https://www.tcpdump.org/linktypes.html)
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_RAW_ALT = 12
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229

ETH_IPV4, ETH_IPV6 = 0x0800, 0x86DD
VLAN_TYPES = (0x8100, 0x88A8, 0x9100)
PROTO_TCP, PROTO_UDP = 6, 17


@dataclass
class Packet:
    ts: float
    size: int
    src: str
    dst: str
    proto: int
    sport: int = 0
    dport: int = 0
    tcp_flags: int = 0

    @property
    def key(self) -> tuple:
        return (self.src, self.dst, self.proto, self.sport, self.dport)


class PcapError(ValueError):
    pass


# ---------------------------------------------------------------- decoding

def _parse_ip(data: bytes, ts: float, size: int) -> Optional[Packet]:
    if not data:
        return None
    version = data[0] >> 4
    if version == 4 and len(data) >= 20:
        ihl = (data[0] & 0x0F) * 4
        proto = data[9]
        src = socket.inet_ntop(socket.AF_INET, data[12:16])
        dst = socket.inet_ntop(socket.AF_INET, data[16:20])
        frag_offset = struct.unpack("!H", data[6:8])[0] & 0x1FFF
        payload = data[ihl:] if frag_offset == 0 else b""
    elif version == 6 and len(data) >= 40:
        proto = data[6]
        src = socket.inet_ntop(socket.AF_INET6, data[8:24])
        dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
        payload = data[40:]
    else:
        return None

    pkt = Packet(ts=ts, size=size, src=src, dst=dst, proto=proto)
    if proto in (PROTO_TCP, PROTO_UDP) and len(payload) >= 4:
        pkt.sport, pkt.dport = struct.unpack("!HH", payload[:4])
        if proto == PROTO_TCP and len(payload) >= 14:
            pkt.tcp_flags = payload[13]
    return pkt


def decode_frame(linktype: int, frame: bytes, ts: float, size: int) -> Optional[Packet]:
    """Decode one captured frame. Returns None for anything that isn't IP."""
    if linktype == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        offset = 12
        ethertype = struct.unpack("!H", frame[offset:offset + 2])[0]
        while ethertype in VLAN_TYPES and len(frame) >= offset + 6:
            offset += 4
            ethertype = struct.unpack("!H", frame[offset:offset + 2])[0]
        if ethertype not in (ETH_IPV4, ETH_IPV6):
            return None
        return _parse_ip(frame[offset + 2:], ts, size)
    if linktype == LINKTYPE_NULL:
        return _parse_ip(frame[4:], ts, size)
    if linktype in (LINKTYPE_RAW, LINKTYPE_RAW_ALT, LINKTYPE_IPV4, LINKTYPE_IPV6):
        return _parse_ip(frame, ts, size)
    if linktype == LINKTYPE_LINUX_SLL:
        if len(frame) < 16 or struct.unpack("!H", frame[14:16])[0] not in (ETH_IPV4, ETH_IPV6):
            return None
        return _parse_ip(frame[16:], ts, size)
    if linktype == LINKTYPE_LINUX_SLL2:
        if len(frame) < 20 or struct.unpack("!H", frame[0:2])[0] not in (ETH_IPV4, ETH_IPV6):
            return None
        return _parse_ip(frame[20:], ts, size)
    return None


# ---------------------------------------------------------------- file formats

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"


def _read_pcap(f, magic: bytes) -> Iterator[Packet]:
    endian, resolution = PCAP_MAGICS[magic]
    header = f.read(20)
    if len(header) < 20:
        raise PcapError("truncated pcap header")
    linktype = struct.unpack(endian + "I", header[16:20])[0] & 0x0FFFFFFF
    rec = struct.Struct(endian + "IIII")
    while True:
        h = f.read(16)
        if len(h) < 16:
            return
        sec, frac, incl, _orig = rec.unpack(h)
        frame = f.read(incl)
        if len(frame) < incl:
            return  # truncated final packet
        pkt = decode_frame(linktype, frame, sec + frac * resolution, incl)
        if pkt:
            yield pkt


def _read_pcapng(f) -> Iterator[Packet]:
    endian = "<"
    interfaces = []  # (linktype, seconds per tick)
    first = True
    while True:
        head = f.read(8)
        if len(head) < 8:
            return
        if head[:4] == PCAPNG_SHB:
            bom = f.read(4)
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            block_len = struct.unpack(endian + "I", head[4:8])[0]
            f.read(block_len - 12)
            interfaces = []
            first = False
            continue
        if first:
            raise PcapError("pcapng file does not start with a section header")
        btype, block_len = struct.unpack(endian + "II", head)
        if block_len < 12:
            raise PcapError("corrupt pcapng block")
        body = f.read(block_len - 8)
        if len(body) < block_len - 8:
            return
        body = body[:-4]  # trailing copy of the block length

        if btype == 1:  # Interface Description Block
            linktype = struct.unpack(endian + "H", body[0:2])[0]
            tick = 1e-6
            opts = body[8:]
            i = 0
            while i + 4 <= len(opts):
                code, length = struct.unpack(endian + "HH", opts[i:i + 4])
                if code == 0:
                    break
                if code == 9 and length >= 1:  # if_tsresol
                    v = opts[i + 4]
                    tick = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                i += 4 + ((length + 3) & ~3)
            interfaces.append((linktype, tick))
        elif btype == 6:  # Enhanced Packet Block
            iface, hi, lo, cap_len, _orig = struct.unpack(endian + "IIIII", body[:20])
            if iface >= len(interfaces):
                continue
            linktype, tick = interfaces[iface]
            ts = ((hi << 32) | lo) * tick
            pkt = decode_frame(linktype, body[20:20 + cap_len], ts, cap_len)
            if pkt:
                yield pkt
        elif btype == 3 and interfaces:  # Simple Packet Block (no timestamp)
            _orig = struct.unpack(endian + "I", body[:4])[0]
            frame = body[4:]
            pkt = decode_frame(interfaces[0][0], frame, 0.0, len(frame))
            if pkt:
                yield pkt


def read_packets(path) -> Iterator[Packet]:
    """Yield the IP packets in a .pcap or .pcapng file, in file order."""
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic in PCAP_MAGICS:
            yield from _read_pcap(f, magic)
        elif magic == PCAPNG_SHB:
            f.seek(0)
            yield from _read_pcapng(f)
        else:
            raise PcapError(f"{Path(path).name} is not a pcap or pcapng file")


# ---------------------------------------------------------------- writing

class PcapWriter:
    """Writes Ethernet/IPv4 packets to a classic .pcap file (for sample data and tests)."""

    def __init__(self, path):
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))

    def write(self, ts: float, src: str, dst: str, proto: int, sport: int = 0, dport: int = 0,
              tcp_flags: int = 0, payload_len: int = 0) -> None:
        if proto == PROTO_TCP:
            l4 = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, tcp_flags, 65535, 0, 0)
        elif proto == PROTO_UDP:
            l4 = struct.pack("!HHHH", sport, dport, 8 + payload_len, 0)
        else:
            l4 = struct.pack("!BBHI", 8, 0, 0, 0)  # ICMP echo
        body = l4 + b"\x00" * payload_len
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 0, 0, 64, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
        frame = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00" + ip + body
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        if usec >= 1_000_000:
            sec, usec = sec + 1, usec - 1_000_000
        self.f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame)

    def close(self) -> None:
        self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
