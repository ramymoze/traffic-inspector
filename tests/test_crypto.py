import pytest

from server import protocol as proto
from server.crypto import (
    CryptoError,
    SessionCrypto,
    ack_proof,
    derive_session_key,
    hello_proof,
    load_master_key,
    seal_with_master,
    unseal_with_master,
)


def test_master_key_is_created_and_reused(tmp_path):
    env_file = tmp_path / ".env"
    first = load_master_key(env_file)
    assert len(first) == 32
    assert env_file.exists()
    second = load_master_key(env_file)
    assert first == second


def test_master_key_prefers_the_environment(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    monkeypatch.setenv("TRAFFIC_INSPECTOR_KEY", "11" * 32)
    assert load_master_key(env_file) == bytes.fromhex("11" * 32)


def test_session_crypto_round_trip():
    key = bytes(range(32))
    client = SessionCrypto(key, send_id=b"c" * 8, recv_id=b"s" * 8)
    server = SessionCrypto(key, send_id=b"s" * 8, recv_id=b"c" * 8)

    header = proto.build_header(proto.DATA, 7, 5)
    wire = client.encrypt(header, b"hello")
    got_header, payload = server.decrypt(wire)
    assert payload == b"hello"
    assert got_header == header


def test_tampered_ciphertext_is_rejected():
    key = bytes(range(32))
    client = SessionCrypto(key, send_id=b"c" * 8, recv_id=b"s" * 8)
    server = SessionCrypto(key, send_id=b"s" * 8, recv_id=b"c" * 8)

    header = proto.build_header(proto.DATA, 7, 5)
    wire = bytearray(client.encrypt(header, b"hello"))
    wire[proto.HEADER_LEN + proto.NONCE_LEN] ^= 0x01
    with pytest.raises(CryptoError):
        server.decrypt(bytes(wire))


def test_tampered_header_is_rejected():
    """The header is authenticated, so a rewritten flow id is caught."""
    key = bytes(range(32))
    client = SessionCrypto(key, send_id=b"c" * 8, recv_id=b"s" * 8)
    server = SessionCrypto(key, send_id=b"s" * 8, recv_id=b"c" * 8)

    header = proto.build_header(proto.DATA, 7, 5)
    wire = bytearray(client.encrypt(header, b"hello"))
    wire[8] ^= 0x01  # flip a bit inside the flow id
    with pytest.raises(CryptoError):
        server.decrypt(bytes(wire))


def test_replayed_frame_is_rejected():
    """A frame that comes twice must not be taken twice."""
    key = bytes(range(32))
    client = SessionCrypto(key, send_id=b"c" * 8, recv_id=b"s" * 8)
    server = SessionCrypto(key, send_id=b"s" * 8, recv_id=b"c" * 8)

    header = proto.build_header(proto.DATA, 7, 5)
    wire = client.encrypt(header, b"hello")
    assert server.decrypt(wire) is not None
    # the same frame again: it is not for us any more
    assert server.decrypt(wire) is None


def test_handshake_proofs():
    master = bytes(range(32))
    client_id = b"c" * 8
    server_id = b"s" * 8
    client_nonce = b"n" * 8
    server_nonce = b"m" * 8
    assert hello_proof(master, client_id, client_nonce) == hello_proof(
        master, client_id, client_nonce
    )
    assert hello_proof(master, client_id, client_nonce) != hello_proof(
        master, client_id, server_nonce
    )
    assert ack_proof(master, client_id, server_id, client_nonce, server_nonce) == ack_proof(
        master, client_id, server_id, client_nonce, server_nonce
    )


def test_both_sides_derive_the_same_session_key():
    master = bytes(range(32))
    client_id, server_id = b"c" * 8, b"s" * 8
    client_nonce, server_nonce = b"n" * 8, b"m" * 8
    first = derive_session_key(master, client_id, server_id, client_nonce, server_nonce)
    second = derive_session_key(master, client_id, server_id, client_nonce, server_nonce)
    assert first == second
    assert len(first) == 32


def test_handshake_frame_is_sealed_with_the_master_key():
    master = bytes(range(32))
    header = proto.build_header(proto.HELLO, 0, 4)
    wire = seal_with_master(master, header, b"ping")
    got_header, payload = unseal_with_master(master, wire)
    assert payload == b"ping"
    assert got_header == header
    with pytest.raises(CryptoError):
        unseal_with_master(bytes(32), wire)


def test_the_device_label_is_authenticated():
    """The label travels inside the sealed frame, so it cannot be changed."""
    master = bytes(range(32))
    payload = proto.build_hello(b"c" * 8, b"n" * 8, b"p" * 16, "pixel8-android")
    header = proto.build_header(proto.HELLO, 0, len(payload))
    wire = bytearray(seal_with_master(master, header, payload))
    wire[-1] ^= 0x01  # change the last letter of the label
    with pytest.raises(CryptoError):
        unseal_with_master(master, bytes(wire))
