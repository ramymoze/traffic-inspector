"""Wire protocol for the traffic-inspector tunnel.

Frame layout on the wire (all integers big endian)::

    +--------+--------+--------+--------+----------+-------------+
    | ver(1) | type(1)| flags(1)| rsv(1)  | len(2)   | flow_id(4)  |
    +--------+--------+--------+--------+----------+-------------+
    | nonce(12) | ciphertext(len) | tag(16)                       |
    +-----------+------------------+------------------------------+

The 10 byte header travels in the clear but is authenticated as GCM
Additional Authenticated Data, so an on-path attacker cannot rewrite a frame
type or a flow id without invalidating the tag.
"""

import socket
import struct

VERSION = 1

HEADER_LEN = 10
NONCE_LEN = 12
TAG_LEN = 16

#: Largest plaintext payload carried by a single frame.  Keeps the whole
#: datagram comfortably below the 1500 byte path MTU.
MAX_DATA = 1200

#: Largest wire frame we are willing to accept.
MAX_FRAME = HEADER_LEN + NONCE_LEN + MAX_DATA + TAG_LEN

# --- frame types -----------------------------------------------------------
HELLO = 0x00  # client -> server, encrypted with the master key
HELLO_ACK = 0x01  # server -> client, encrypted with the master key
OPEN = 0x02  # client -> server, opens a new flow
OPEN_OK = 0x03  # server -> client, result of OPEN
DATA = 0x04  # both directions, payload bytes
CLOSE = 0x05  # both directions, flow teardown
PING = 0x06  # both directions, keepalive
PONG = 0x07  # both directions, keepalive answer
REPORT_REQ = 0x08  # client -> server, asks for the report
REPORT_RES = 0x09  # server -> client, the report in pieces

TYPE_NAMES = {
    HELLO: "HELLO",
    HELLO_ACK: "HELLO_ACK",
    OPEN: "OPEN",
    OPEN_OK: "OPEN_OK",
    DATA: "DATA",
    CLOSE: "CLOSE",
    PING: "PING",
    PONG: "PONG",
    REPORT_REQ: "REPORT_REQ",
    REPORT_RES: "REPORT_RES",
}

# --- OPEN_OK status codes --------------------------------------------------
OK = 0
ERR_BAD_REQUEST = 1
ERR_RESOLVE = 2
ERR_REFUSED = 3
ERR_TIMEOUT = 4
ERR_CONNECT = 5
ERR_UNSUPPORTED = 6
ERR_EXISTS = 7
ERR_LIMIT = 8

STATUS_NAMES = {
    OK: "ok",
    ERR_BAD_REQUEST: "bad request",
    ERR_RESOLVE: "destination name could not be resolved",
    ERR_REFUSED: "connection refused",
    ERR_TIMEOUT: "connection timed out",
    ERR_CONNECT: "connection failed",
    ERR_UNSUPPORTED: "protocol not supported",
    ERR_EXISTS: "flow already exists",
    ERR_LIMIT: "too many flows",
}

# --- CLOSE reason codes ----------------------------------------------------
CLOSE_NORMAL = 0
CLOSE_ERROR = 1
CLOSE_TIMEOUT = 2
CLOSE_RESET = 3
CLOSE_SHUTDOWN = 4

CLOSE_NAMES = {
    CLOSE_NORMAL: "normal",
    CLOSE_ERROR: "error",
    CLOSE_TIMEOUT: "timeout",
    CLOSE_RESET: "reset by peer",
    CLOSE_SHUTDOWN: "server shutdown",
}

# --- address families ------------------------------------------------------
AF_ANY = 0x00
AF_IPV4 = 0x01
AF_DOMAIN = 0x03
AF_IPV6 = 0x04

# --- transport protocols ----------------------------------------------------
IPPROTO_TCP = 6
IPPROTO_UDP = 17

#: DATA frames carrying a UDP datagram set this flag.  Their payload starts
#: with a 2 byte big endian total datagram length followed by a chunk, so a
#: datagram larger than one frame can be reassembled by the receiver.
FLAG_DATAGRAM = 0x01

#: A REPORT_RES frame carries a piece of the report.  Its payload starts with
#: one byte of flags, four bytes of the offset of the piece in the whole
#: report and four bytes of the length of the whole report, so the receiver
#: can put the pieces back together even when they arrive out of order.
REPORT_HEADER_LEN = 9

#: Set on the last piece of the report.
FLAG_LAST = 0x01


class ProtocolError(Exception):
    """Raised when a frame cannot be parsed or is malformed."""


# --- the HELLO payload ----------------------------------------------------
HELLO_ID_LEN = 8
HELLO_NONCE_LEN = 8
HELLO_PROOF_LEN = 16
HELLO_MIN_LEN = HELLO_ID_LEN + HELLO_NONCE_LEN + HELLO_PROOF_LEN

#: The longest device label a client may send.
LABEL_MAX = 255


def encode_label(label):
    """Encode a device label: one length byte and the name."""
    if not label:
        return b"\x00"
    raw = str(label).encode("utf-8")[:LABEL_MAX]
    return bytes([len(raw)]) + raw


def decode_label(payload, offset=0):
    """Decode a device label.  Returns ``(label, next_offset)``."""
    if offset >= len(payload):
        return "", offset
    length = payload[offset]
    offset += 1
    raw = payload[offset:offset + length]
    return raw.decode("utf-8", "replace"), offset + length


def build_hello(client_id, client_nonce, proof, label=""):
    """Build the payload of a HELLO frame."""
    if len(client_id) != HELLO_ID_LEN or len(client_nonce) != HELLO_NONCE_LEN:
        raise ProtocolError("the client id and the nonce must be %d bytes" % HELLO_ID_LEN)
    if len(proof) != HELLO_PROOF_LEN:
        raise ProtocolError("the proof must be %d bytes" % HELLO_PROOF_LEN)
    return client_id + client_nonce + proof + encode_label(label)


def parse_hello(payload):
    """Parse the payload of a HELLO frame.

    Returns ``(client_id, client_nonce, proof, label)``.  The label is only
    a name the client gives itself, the server cannot verify it.
    """
    if len(payload) < HELLO_MIN_LEN:
        raise ProtocolError("short HELLO payload")
    client_id = payload[:HELLO_ID_LEN]
    client_nonce = payload[HELLO_ID_LEN:HELLO_ID_LEN + HELLO_NONCE_LEN]
    proof = payload[
        HELLO_ID_LEN + HELLO_NONCE_LEN:HELLO_ID_LEN + HELLO_NONCE_LEN + HELLO_PROOF_LEN
    ]
    label, _ = decode_label(payload, HELLO_MIN_LEN)
    return client_id, client_nonce, proof, label


def type_name(ftype):
    return TYPE_NAMES.get(ftype, "UNKNOWN(0x%02x)" % ftype)


def status_name(status):
    return STATUS_NAMES.get(status, "unknown(%d)" % status)


def close_name(reason):
    return CLOSE_NAMES.get(reason, "unknown(%d)" % reason)


# --- the report ------------------------------------------------------------
def build_report_chunk(text, offset, total, last=False):
    """Build the payload of a REPORT_RES frame.

    ``text`` is the piece of the report, ``offset`` where it belongs in the
    whole report and ``total`` how long the whole report is.
    """
    flags = FLAG_LAST if last else 0
    return bytes([flags]) + struct.pack("!II", offset, total) + text


def parse_report_chunk(payload):
    """Parse the payload of a REPORT_RES frame into a dict."""
    if len(payload) < REPORT_HEADER_LEN:
        raise ProtocolError("short REPORT payload")
    flags = payload[0]
    offset, total = struct.unpack("!II", payload[1:REPORT_HEADER_LEN])
    return {
        "last": bool(flags & FLAG_LAST),
        "offset": offset,
        "total": total,
        "text": payload[REPORT_HEADER_LEN:],
    }


def close_name(reason):
    return CLOSE_NAMES.get(reason, "unknown(%d)" % reason)


def build_header(ftype, flow_id, length, flags=0):
    """Return the 10 byte frame header (authenticated as AAD)."""
    return struct.pack("!BBBBHI", VERSION, ftype, flags, 0, length, flow_id & 0xFFFFFFFF)


def parse_header(header):
    """Parse a frame header into a dict."""
    if len(header) < HEADER_LEN:
        raise ProtocolError("short header")
    version, ftype, flags, rsv, length, flow_id = struct.unpack("!BBBBHI", header[:HEADER_LEN])
    if version != VERSION:
        raise ProtocolError("unsupported protocol version %d" % version)
    if rsv != 0:
        raise ProtocolError("reserved bits set")
    if length > MAX_DATA:
        raise ProtocolError("payload too large (%d bytes)" % length)
    return {
        "version": version,
        "type": ftype,
        "flags": flags,
        "length": length,
        "flow_id": flow_id,
    }


# --- address encoding ------------------------------------------------------
def encode_address(family, address):
    """Encode an address into the wire format.  Returns bytes."""
    if family == AF_ANY:
        return bytes([AF_ANY])
    if family == AF_IPV4:
        return bytes([AF_IPV4]) + socket.inet_aton(address)
    if family == AF_IPV6:
        return bytes([AF_IPV6]) + socket.inet_pton(socket.AF_INET6, address)
    if family == AF_DOMAIN:
        raw = address.encode("idna") if any(ord(c) > 127 for c in address) else address.encode()
        if len(raw) > 255:
            raise ProtocolError("destination name too long")
        return bytes([AF_DOMAIN, len(raw)]) + raw
    raise ProtocolError("unsupported address family %r" % (family,))


def decode_address(buf, offset):
    """Decode an address at ``offset``.

    Returns ``(family, address, next_offset)`` where ``address`` is a string
    (dotted quad, host name, ...) or ``None`` for AF_ANY.
    """
    if offset >= len(buf):
        raise ProtocolError("truncated address")
    family = buf[offset]
    offset += 1
    if family == AF_ANY:
        return AF_ANY, None, offset
    if family == AF_IPV4:
        if offset + 4 > len(buf):
            raise ProtocolError("truncated IPv4 address")
        return AF_IPV4, socket.inet_ntoa(buf[offset:offset + 4]), offset + 4
    if family == AF_IPV6:
        if offset + 16 > len(buf):
            raise ProtocolError("truncated IPv6 address")
        return AF_IPV6, socket.inet_ntop(socket.AF_INET6, buf[offset:offset + 16]), offset + 16
    if family == AF_DOMAIN:
        if offset >= len(buf):
            raise ProtocolError("truncated host name")
        length = buf[offset]
        offset += 1
        if offset + length > len(buf):
            raise ProtocolError("truncated host name")
        return AF_DOMAIN, buf[offset:offset + length].decode("utf-8", "replace"), offset + length
    raise ProtocolError("unsupported address family %d" % family)


def build_open(protocol, src_ip, src_port, dst_ip, dst_port, dst_name=None):
    """Build the payload of an OPEN frame.

    ``dst_name`` lets the client ask the server to resolve the destination
    itself, which keeps DNS out of the tunnel (and gives the inspector a
    human readable destination).
    """
    if dst_name:
        dst_family = AF_DOMAIN
        dst_address = dst_name
    elif dst_ip and ":" in dst_ip:
        dst_family = AF_IPV6
        dst_address = dst_ip
    elif dst_ip:
        dst_family = AF_IPV4
        dst_address = dst_ip
    else:
        dst_family = AF_ANY
        dst_address = None

    if src_ip:
        src_family = AF_IPV6 if ":" in src_ip else AF_IPV4
    else:
        src_family = AF_ANY

    payload = bytes([protocol])
    payload += encode_address(src_family, src_ip) if src_ip else encode_address(AF_ANY, None)
    payload += struct.pack("!H", src_port & 0xFFFF)
    payload += encode_address(dst_family, dst_address)
    payload += struct.pack("!H", dst_port & 0xFFFF)
    return payload


def decode_open(payload):
    """Decode the payload of an OPEN frame into a dict."""
    if len(payload) < 1:
        raise ProtocolError("empty OPEN payload")
    protocol = payload[0]
    offset = 1
    src_family, src_ip, offset = decode_address(payload, offset)
    if offset + 2 > len(payload):
        raise ProtocolError("truncated source port")
    src_port = struct.unpack("!H", payload[offset:offset + 2])[0]
    offset += 2
    dst_family, dst_value, offset = decode_address(payload, offset)
    if offset + 2 > len(payload):
        raise ProtocolError("truncated destination port")
    dst_port = struct.unpack("!H", payload[offset:offset + 2])[0]
    offset += 2

    if protocol == IPPROTO_TCP:
        proto_name = "TCP"
    elif protocol == IPPROTO_UDP:
        proto_name = "UDP"
    else:
        proto_name = "IP(%d)" % protocol

    dst_name = dst_value if dst_family == AF_DOMAIN else None
    dst_ip = dst_value if dst_family in (AF_IPV4, AF_IPV6) else None

    return {
        "protocol": protocol,
        "proto_name": proto_name,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "dst_name": dst_name,
    }
