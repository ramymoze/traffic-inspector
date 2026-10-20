import pytest

from server import protocol as proto


def test_header_round_trip():
    header = proto.build_header(proto.DATA, 0xDEADBEEF, 1000, proto.FLAG_DATAGRAM)
    parsed = proto.parse_header(header)
    assert parsed["version"] == proto.VERSION
    assert parsed["type"] == proto.DATA
    assert parsed["flags"] == proto.FLAG_DATAGRAM
    assert parsed["length"] == 1000
    assert parsed["flow_id"] == 0xDEADBEEF


def test_header_rejects_wrong_version():
    header = bytearray(proto.build_header(proto.DATA, 1, 0))
    header[0] = 99
    with pytest.raises(proto.ProtocolError):
        proto.parse_header(bytes(header))


def test_header_rejects_oversized_payload():
    header = proto.build_header(proto.DATA, 1, proto.MAX_DATA + 1)
    with pytest.raises(proto.ProtocolError):
        proto.parse_header(header)


def test_open_payload_round_trip_ipv4():
    payload = proto.build_open(
        proto.IPPROTO_TCP, "10.8.0.2", 52344, "142.250.200.164", 443
    )
    params = proto.decode_open(payload)
    assert params["protocol"] == proto.IPPROTO_TCP
    assert params["proto_name"] == "TCP"
    assert params["src_ip"] == "10.8.0.2"
    assert params["src_port"] == 52344
    assert params["dst_ip"] == "142.250.200.164"
    assert params["dst_port"] == 443
    assert params["dst_name"] is None


def test_open_payload_round_trip_domain():
    payload = proto.build_open(
        proto.IPPROTO_UDP, "10.8.0.2", 5353, None, 53, dst_name="dns.example.com"
    )
    params = proto.decode_open(payload)
    assert params["dst_name"] == "dns.example.com"
    assert params["dst_ip"] is None
    assert params["dst_port"] == 53
    assert params["proto_name"] == "UDP"


def test_open_payload_round_trip_ipv6():
    payload = proto.build_open(proto.IPPROTO_TCP, None, 0, "2001:db8::1", 80)
    params = proto.decode_open(payload)
    assert params["dst_ip"] == "2001:db8::1"
    assert params["src_ip"] is None


def test_open_payload_rejects_truncated_data():
    payload = proto.build_open(proto.IPPROTO_TCP, "10.8.0.2", 1234, "1.2.3.4", 80)
    with pytest.raises(proto.ProtocolError):
        proto.decode_open(payload[:5])


def test_a_device_label_survives_the_round_trip():
    payload = proto.build_hello(b"c" * 8, b"n" * 8, b"p" * 16, "pixel8-android")
    client_id, client_nonce, proof, label = proto.parse_hello(payload)
    assert client_id == b"c" * 8
    assert client_nonce == b"n" * 8
    assert proof == b"p" * 16
    assert label == "pixel8-android"


def test_a_hello_without_a_label_is_allowed():
    payload = proto.build_hello(b"c" * 8, b"n" * 8, b"p" * 16, "")
    _client_id, _nonce, _proof, label = proto.parse_hello(payload)
    assert label == ""


def test_a_label_with_odd_characters_is_kept():
    payload = proto.build_hello(b"c" * 8, b"n" * 8, b"p" * 16, "tél-phone-1")
    _client_id, _nonce, _proof, label = proto.parse_hello(payload)
    assert label == "tél-phone-1"


def test_a_too_long_label_is_cut():
    payload = proto.build_hello(b"c" * 8, b"n" * 8, b"p" * 16, "x" * 400)
    _client_id, _nonce, _proof, label = proto.parse_hello(payload)
    assert len(label) == proto.LABEL_MAX


def test_a_short_hello_is_rejected():
    with pytest.raises(proto.ProtocolError):
        proto.parse_hello(b"too short")
