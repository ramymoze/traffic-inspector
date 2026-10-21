"""The report, asked for over the tunnel.

The phone does not read the file of the server, it asks the server for the
report and the server sends it back in pieces.
"""

import time

from client.tunnel import TunnelClient
from server import protocol as proto


def connect(server, master, device="pixel8-android"):
    client = TunnelClient(
        ("127.0.0.1", server.udp.getsockname()[1]), master, device=device
    )
    client.handshake()
    return client


def test_the_report_comes_back_over_the_tunnel(server, master):
    """The client asks, the server answers with the text of the report."""
    client = connect(server, master)

    # some traffic, so the report has something to say
    client.open_flow("127.0.0.1", 9, src_ip="10.8.0.2", src_port=1234)
    client.pump(timeout=0.3)
    server.inspector.maybe_write(force=True)

    client.request_report()
    text = client.wait_for_report(timeout=20)

    assert "traffic-inspector" in text
    assert "pixel8-android" in text
    client.close()


def test_the_report_is_only_for_the_devices_that_know_the_key(server, master, tmp_path):
    """A client that cannot talk to the server cannot ask for a report."""
    from server.crypto import load_master_key

    other_key = load_master_key(str(tmp_path / "other.env"))
    client = TunnelClient(
        ("127.0.0.1", server.udp.getsockname()[1]), other_key, device="stranger"
    )
    try:
        client.handshake()
    except Exception:
        return  # the handshake failed, which is the point
    client.request_report()
    try:
        client.wait_for_report(timeout=2)
    except Exception:
        return
    raise AssertionError("a client with the wrong key got a report")


def test_a_piece_of_the_report_carries_its_place():
    """The pieces have to be put back together, so they say where they go."""
    chunk = proto.build_report_chunk(b"hello", 100, 250, last=False)
    parsed = proto.parse_report_chunk(chunk)
    assert parsed["offset"] == 100
    assert parsed["total"] == 250
    assert parsed["text"] == b"hello"
    assert parsed["last"] is False

    last = proto.parse_report_chunk(proto.build_report_chunk(b"!", 249, 250, last=True))
    assert last["last"] is True


def test_the_report_fits_in_pieces():
    """A long report is cut into pieces that fit into one frame."""
    from server import report as report_module

    text = "x" * 5000
    room = proto.MAX_DATA - proto.REPORT_HEADER_LEN
    pieces = [
        text[offset:offset + room] for offset in range(0, len(text), room)
    ]
    assert len(pieces) > 1
    for piece in pieces:
        payload = proto.build_report_chunk(piece.encode(), 0, len(text))
        assert len(payload) <= proto.MAX_DATA
