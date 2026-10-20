"""Shared fixtures for the test suite."""

import socket
import threading
import time

import pytest

from server.crypto import load_master_key
from server.server import TunnelServer


def start_echo_server():
    """A TCP server that answers with the upper case of what it received."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    port = listener.getsockname()[1]

    def _handle(conn):
        with conn:
            while True:
                try:
                    data = conn.recv(4096)
                except OSError:
                    return
                if not data:
                    return
                try:
                    conn.sendall(data.upper())
                except OSError:
                    return

    def serve():
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            threading.Thread(target=_handle, args=(conn,), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    return listener, port


@pytest.fixture
def server(tmp_path):
    key_file = tmp_path / ".env"
    instance = TunnelServer(
        host="127.0.0.1",
        port=0,
        csv_path=str(tmp_path / "traffic.csv"),
        key_file=str(key_file),
        level="quiet",
    )
    thread = threading.Thread(target=instance.run, daemon=True)
    thread.start()
    time.sleep(0.2)
    yield instance
    instance.running = False
    thread.join(timeout=2)


@pytest.fixture
def master(server, tmp_path):
    """The key the server generated, read back from the env file."""
    return load_master_key(str(tmp_path / ".env"))


@pytest.fixture
def echo_server():
    listener, port = start_echo_server()
    yield listener, port
    listener.close()
