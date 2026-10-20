import socket
import struct
import threading
import time

from client.socks import SocksProxy
from client.tunnel import TunnelClient
from server import protocol as proto


def connect(server, master):
    client = TunnelClient(("127.0.0.1", server.udp.getsockname()[1]), master)
    client.handshake()
    return client


def wait_for_status(client, flows, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        client.pump(timeout=0.1)
        if all(flow.status is not None for flow in flows):
            return
    for flow in flows:
        assert flow.status is not None, "the server never answered the OPEN"


def socks_request(host, port, destination, destination_port):
    """Do a SOCKS5 handshake and ask for a connection.  Returns the socket."""
    conn = socket.create_connection((host, port), timeout=10)
    conn.sendall(b"\x05\x01\x00")
    assert conn.recv(2) == b"\x05\x00"
    request = (
        b"\x05\x01\x00\x01"
        + socket.inet_aton(destination)
        + struct.pack("!H", destination_port)
    )
    conn.sendall(request)
    return conn


def test_a_socks_request_travels_through_the_tunnel(server, master, echo_server):
    _listener, echo_port = echo_server
    client = connect(server, master)
    client.start_pump()

    proxy = SocksProxy(client, "127.0.0.1", 0, verbose=False)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    time.sleep(0.2)
    proxy_host, proxy_port = proxy.address

    conn = socks_request(proxy_host, proxy_port, "127.0.0.1", echo_port)
    conn.settimeout(10)
    answer = conn.recv(10)
    assert answer[0] == 0x05
    assert answer[1] == 0x00  # success

    conn.sendall(b"through the tunnel")
    data = b""
    while len(data) < len(b"through the tunnel"):
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    assert data == b"THROUGH THE TUNNEL"
    conn.close()
    client.close()


def test_the_socks_proxy_records_the_flow(server, master, echo_server, tmp_path):
    _listener, echo_port = echo_server
    client = connect(server, master)
    client.start_pump()

    proxy = SocksProxy(client, "127.0.0.1", 0, verbose=False)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    time.sleep(0.2)
    proxy_host, proxy_port = proxy.address

    conn = socks_request(proxy_host, proxy_port, "127.0.0.1", echo_port)
    conn.settimeout(10)
    conn.recv(10)
    conn.sendall(b"hello")
    conn.recv(4096)
    conn.close()

    deadline = time.time() + 5
    while time.time() < deadline:
        server.inspector.maybe_write(force=True)
        rows = server.inspector.rows()
        if rows:
            break
        time.sleep(0.1)
    client.close()

    assert rows, "the flow was not recorded"
    row = rows[0]
    assert row["dst_port"] == str(echo_port)
    assert row["proto"] == "TCP"
    assert row["state"] in ("active", "closed")
    assert int(row["bytes_up"]) > 0
