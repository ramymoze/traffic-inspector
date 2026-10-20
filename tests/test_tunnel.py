import socket
import threading
import time

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


def test_handshake_succeeds(server, master):
    client = connect(server, master)
    assert client.server_id is not None
    client.close()


def test_two_flows_to_two_destinations_stay_separate(server, master, echo_server):
    """The v1 server kept one socket per client, so the second destination
    could never be reached.  Every flow must own its own socket."""
    listener_a, port_a = echo_server
    listener_b, port_b = start_second_echo_server()
    client = connect(server, master)

    flow_a = client.open_flow("127.0.0.1", port_a, src_ip="10.8.0.2", src_port=1111)
    flow_b = client.open_flow("127.0.0.1", port_b, src_ip="10.8.0.2", src_port=2222)
    wait_for_status(client, [flow_a, flow_b])
    assert flow_a.status == proto.OK
    assert flow_b.status == proto.OK

    client.send(flow_a.flow_id, b"alpha")
    client.send(flow_b.flow_id, b"beta")

    received = {flow_a.flow_id: b"", flow_b.flow_id: b""}

    def on_data(flow, data, is_datagram):
        received[flow.flow_id] += data

    deadline = time.time() + 5
    while time.time() < deadline:
        client.pump(timeout=0.1, on_data=on_data)
        if received[flow_a.flow_id] and received[flow_b.flow_id]:
            break
    client.close()

    assert received[flow_a.flow_id] == b"ALPHA"
    assert received[flow_b.flow_id] == b"BETA"


def start_second_echo_server():
    from conftest import start_echo_server

    return start_echo_server()


def test_a_refused_connection_is_reported(server, master):
    """Nothing is listening on this port, the client must be told."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    dead_port = probe.getsockname()[1]
    probe.close()

    client = connect(server, master)
    flow = client.open_flow("127.0.0.1", dead_port)
    wait_for_status(client, [flow])
    assert flow.status != proto.OK
    client.close()


def test_the_inspector_records_every_flow(server, master, echo_server, tmp_path):
    _listener, port = echo_server
    client = connect(server, master)
    flow = client.open_flow("127.0.0.1", port, src_ip="10.8.0.2", src_port=4242)
    wait_for_status(client, [flow])
    client.send(flow.flow_id, b"hello")
    client.pump(timeout=0.5)
    client.close()

    server.inspector.maybe_write(force=True)
    content = (tmp_path / "traffic.csv").read_text(encoding="utf-8")
    assert "flow_id" in content
    assert str(flow.flow_id) in content
    assert "10.8.0.2" in content
    assert "4242" in content
