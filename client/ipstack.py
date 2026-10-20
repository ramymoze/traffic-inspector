"""A small IPv4 / TCP codec.

The client needs to read and write real IP packets, but only IPv4 and only
the two protocols a tunnel carries.  A hand written codec keeps the client
dependency free (no scapy) and gives exact control over the sequence
numbers, which is the whole point of the TCP bridge.
"""

import socket
import struct

PROTO_TCP = 6
PROTO_UDP = 17

# TCP flags
FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_RST = 0x04
FLAG_PSH = 0x08
FLAG_ACK = 0x10
FLAG_URG = 0x20

FLAG_NAMES = [
    (FLAG_FIN, "FIN"),
    (FLAG_SYN, "SYN"),
    (FLAG_RST, "RST"),
    (FLAG_PSH, "PSH"),
    (FLAG_ACK, "ACK"),
    (FLAG_URG, "URG"),
]


def flag_names(flags):
    return "|".join(name for bit, name in FLAG_NAMES if flags & bit) or "-"


def checksum(data):
    """The standard internet checksum."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for value in struct.unpack("!%dH" % (len(data) // 2), data):
        total += value
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def mss_option(mss):
    """The TCP MSS option (kind 2, length 4)."""
    return b"\x02\x04" + struct.pack("!H", mss)


def parse_ipv4(data):
    """Parse an IPv4 packet.

    Returns ``(src, dst, protocol, payload)`` where ``payload`` is the TCP or
    UDP header plus its data.
    """
    if len(data) < 20:
        raise ValueError("the packet is too short to be IPv4")
    version_ihl = data[0]
    version = version_ihl >> 4
    if version != 4:
        raise ValueError("only IPv4 is supported, got version %d" % version)
    header_length = (version_ihl & 0x0F) * 4
    if header_length < 20 or len(data) < header_length:
        raise ValueError("broken IPv4 header")
    total_length = struct.unpack("!H", data[2:4])[0]
    if total_length and total_length > len(data):
        raise ValueError("truncated IPv4 packet")
    protocol = data[9]
    src = socket.inet_ntoa(data[12:16])
    dst = socket.inet_ntoa(data[16:20])
    end = total_length if total_length else len(data)
    return src, dst, protocol, data[header_length:end]


class TcpHeader:
    __slots__ = ("sport", "dport", "seq", "ack", "flags", "window", "options", "payload")

    def __init__(self, sport, dport, seq, ack, flags, window, options=b"", payload=b""):
        self.sport = sport
        self.dport = dport
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.window = window
        self.options = options
        self.payload = payload

    def __repr__(self):
        return "<TCP %d->%d seq=%d ack=%d %s len=%d>" % (
            self.sport, self.dport, self.seq, self.ack,
            flag_names(self.flags), len(self.payload),
        )


def parse_tcp(data):
    """Parse a TCP header (and its payload)."""
    if len(data) < 20:
        raise ValueError("the TCP header is too short")
    sport, dport, seq, ack = struct.unpack("!HHII", data[:12])
    offset = (data[12] >> 4) * 4
    if offset < 20 or offset > len(data):
        raise ValueError("broken TCP header")
    flags = data[13]
    window = struct.unpack("!H", data[14:16])[0]
    return TcpHeader(
        sport, dport, seq, ack, flags, window, data[20:offset], data[offset:]
    )


def parse_udp(data):
    """Parse a UDP header (and its payload)."""
    if len(data) < 8:
        raise ValueError("the UDP header is too short")
    sport, dport, length, _checksum = struct.unpack("!HHHH", data[:8])
    end = length if length and length <= len(data) else len(data)
    return sport, dport, data[8:end]


def build_tcp_packet(src, dst, sport, dport, seq, ack, flags, window,
                     payload=b"", options=b""):
    """Build a complete IPv4 + TCP packet."""
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
        (5 + len(options) // 4) << 4,
        flags,
        window & 0xFFFF,
        0,  # checksum, filled in below
        0,  # urgent pointer
    )
    tcp_header += options
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack(
        "!BBH", 0, PROTO_TCP, len(tcp_header) + len(payload)
    )
    tcp_checksum = checksum(pseudo + tcp_header + payload)
    tcp_header = tcp_header[:16] + struct.pack("!H", tcp_checksum) + tcp_header[18:]

    total_length = 20 + len(tcp_header) + len(payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_length, 0, 0x4000, 64, PROTO_TCP, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    ip_checksum = checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack("!H", ip_checksum) + ip_header[12:]
    return ip_header + tcp_header + payload


def build_udp_packet(src, dst, sport, dport, payload=b""):
    """Build a complete IPv4 + UDP packet."""
    udp_header = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack(
        "!BBH", 0, PROTO_UDP, 8 + len(payload)
    )
    udp_checksum = checksum(pseudo + udp_header + payload) or 0xFFFF
    udp_header = udp_header[:6] + struct.pack("!H", udp_checksum)
    total_length = 20 + len(udp_header) + len(payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_length, 0, 0x4000, 64, PROTO_UDP, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    ip_header = ip_header[:10] + struct.pack("!H", checksum(ip_header)) + ip_header[12:]
    return ip_header + udp_header + payload
