"""Tests for the TCP bridge.

The kernel side of the bridge is driven by scripted packets, which is what
makes the sequence number arithmetic testable.  The data path itself is
checked against a real server and a real HTTP server.
"""

import socket
import threading
import time

from client.bridge import TcpBridge
from client import ipstack
from client.tunnel import TunnelClient
from server import protocol as proto

CLIENT_IP = "10.8.0.2"
SERVER_IP = "93.184.216.34"
CLIENT_PORT = 1234
SERVER_PORT = 80
KERNEL_ISN = 1000


class FakeFlow:
    def __init__(self, flow_id, dst_host, dst_port, protocol):
        self.flow_id = flow_id
        self.dst_host = dst_host
        self.dst_port = dst_port
        self.protocol = protocol
        self.status = proto.OK
        self.closed = False
        self.bytes_in = 0
        self.bytes_out = 0


class FakeTunnel:
    """Records what the bridge sends and lets the test answer."""

    def __init__(self):
        self.flows = {}
        self.sent = []
        self.closed = []
        self._next = 1

    def open_flow(self, dst_host, dst_port, protocol=proto.IPPROTO_TCP,
                  src_ip=None, src_port=0, resolve=False):
        flow = FakeFlow(self._next, dst_host, dst_port, protocol)
        self._next += 1
        self.flows[flow.flow_id] = flow
        return flow

    def send(self, flow_id, data, datagram=False):
        self.sent.append((flow_id, data))

    def close_flow(self, flow_id, reason=proto.CLOSE_NORMAL):
        self.closed.append(flow_id)


def syn_packet(flags=ipstack.FLAG_SYN, seq=KERNEL_ISN, ack=0, payload=b"",
               src=CLIENT_IP, dst=SERVER_IP):
    return ipstack.build_tcp_packet(
        src=src, dst=dst, sport=CLIENT_PORT, dport=SERVER_PORT,
        seq=seq, ack=ack, flags=flags, window=65535, payload=payload,
        options=ipstack.mss_option(1460),
    )


def parse_one(packet):
    src, dst, _protocol, payload = ipstack.parse_ipv4(packet)
    return src, dst, ipstack.parse_tcp(payload)


def start_http_server(body=b"hello from the server"):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    port = listener.getsockname()[1]

    def handle(conn):
        with conn:
            conn.settimeout(5)
            try:
                request = conn.recv(4096)
            except OSError:
                return
            if not request:
                return
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
                % (len(body), body)
            )

    def serve():
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    return listener, port


# -- the state machine ------------------------------------------------------
def test_a_syn_is_answered_with_a_syn_ack():
    tunnel = FakeTunnel()
    bridge = TcpBridge(tunnel, local_ip=CLIENT_IP)

    bridge.handle_packet(syn_packet())
    packets = bridge.take_output()
    assert len(packets) == 1

    src, dst, tcp = parse_one(packets[0])
    assert src == SERVER_IP
    assert dst == CLIENT_IP
    assert tcp.sport == SERVER_PORT
    assert tcp.dport == CLIENT_PORT
    assert tcp.flags & ipstack.FLAG_SYN
    assert tcp.flags & ipstack.FLAG_ACK
    assert tcp.ack == KERNEL_ISN + 1, "the kernel's sequence must be confirmed"
    assert tcp.seq == 0 or tcp.seq > 0  # the bridge picks its own number


def test_the_syn_ack_advertises_a_small_mss():
    tunnel = FakeTunnel()
    bridge = TcpBridge(tunnel, local_ip=CLIENT_IP, mss=1160)
    bridge.handle_packet(syn_packet())
    _src, _dst, tcp = parse_one(bridge.take_output()[0])
    assert b"\x02\x04" in tcp.options
    mss = int.from_bytes(tcp.options[2:4], "big")
    assert mss == 1160


def test_the_syn_opens_a_flow_towards_the_destination():
    tunnel = FakeTunnel()
    bridge = TcpBridge(tunnel, local_ip=CLIENT_IP)
    bridge.handle_packet(syn_packet())
    assert len(tunnel.flows) == 1
    flow = list(tunnel.flows.values())[0]
    assert flow.dst_host == SERVER_IP
    assert flow.dst_port == SERVER_PORT
    assert flow.protocol == proto.IPPROTO_TCP


def test_a_retransmitted_syn_gets_the_same_answer():
    tunnel = FakeTunnel()
    bridge = TcpBridge(tunnel, local_ip=CLIENT_IP)
    bridge.handle_packet(syn_packet())
    first = bridge.take_output()[0]
    bridge.handle_packet(syn_packet())
    second = bridge.take_output()[0]
    assert parse_one(first)[2].seq == parse_one(second)[2].seq
    assert parse_one(first)[2].ack == parse_one(second)[2].ack


def test_the_payload_is_forwarded_and_acknowledged():
    tunnel = FakeTunnel()
    bridge = TcpBridge(tunnel, local_ip=CLIENT_IP)
    bridge.handle_packet(syn_packet())
    bridge.take_output()
    flow = bridge.tcp_flows[(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)]

    payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    bridge.handle_packet(
        syn_packet(
            flags=ipstack.FLAG_ACK | ipstack.FLAG_PSH,
            seq=KERNEL_ISN + 1,
            ack=flow.client_isn + 1,
            payload=payload,
        )
    )

    assert tunnel.sent, "the payload never reached the tunnel"
    assert tunnel.sent[0][1] == payload

    packets = bridge.take_output()
    assert packets, "the kernel was not acknowledged"
    _src, _dst, ack = parse_one(packets[0])
    assert ack.flags & ipstack.FLAG_ACK
    assert ack.ack == KERNEL_ISN + 1 + len(payload)


def test_data_from_the_tunnel_comes_back_as_a_packet():
    tunnel = FakeTunnel()
    bridge = TcpBridge(tunnel, local_ip=CLIENT_IP)
    bridge.handle_packet(syn_packet())
    bridge.take_output()
    flow = bridge.tcp_flows[(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)]

    bridge.on_tunnel_data(flow.tunnel_flow, b"HTTP/1.1 200 OK\r\n\r\n")
    bridge.pump()

    packets = bridge.take_output()
    assert packets
    src, dst, tcp = parse_one(packets[0])
    assert src == SERVER_IP
    assert dst == CLIENT_IP
    assert tcp.payload == b"HTTP/1.1 200 OK\r\n\r\n"
    assert tcp.seq == flow.client_isn + 1
    assert tcp.ack == KERNEL_ISN + 1
    assert tcp.flags & ipstack.FLAG_ACK


def test_an_unknown_flow_is_refused():
    tunnel = FakeTunnel()
    bridge = TcpBridge(tunnel, local_ip=CLIENT_IP)
    bridge.handle_packet(
        syn_packet(flags=ipstack.FLAG_ACK | ipstack.FLAG_PSH, seq=500, ack=1,
                   payload=b"data without a handshake")
    )
    packets = bridge.take_output()
    assert packets
    _src, _dst, tcp = parse_one(packets[0])
    assert tcp.flags & ipstack.FLAG_RST


def test_a_reset_from_the_kernel_closes_the_flow():
    tunnel = FakeTunnel()
    bridge = TcpBridge(tunnel, local_ip=CLIENT_IP)
    bridge.handle_packet(syn_packet())
    bridge.take_output()
    flow = bridge.tcp_flows[(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)]
    bridge.handle_packet(
        syn_packet(flags=ipstack.FLAG_RST, seq=KERNEL_ISN + 1, ack=flow.client_isn + 1)
    )
    assert (CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT) not in bridge.tcp_flows


# -- the whole chain --------------------------------------------------------
def test_a_real_request_goes_through_the_tunnel(server, master):
    """The bridge, the tunnel, the server and a real HTTP server, end to end."""
    listener, http_port = start_http_server()
    try:
        client = TunnelClient(("127.0.0.1", server.udp.getsockname()[1]), master)
        client.handshake()
        bridge = TcpBridge(client, local_ip=CLIENT_IP)
        client.start_pump(bridge.on_tunnel_data)

        # the kernel opens the connection
        bridge.handle_packet(
            ipstack.build_tcp_packet(
                src=CLIENT_IP, dst="127.0.0.1", sport=CLIENT_PORT, dport=http_port,
                seq=KERNEL_ISN, ack=0, flags=ipstack.FLAG_SYN, window=65535,
                options=ipstack.mss_option(1460),
            )
        )
        bridge.take_output()

        # wait for the server to open its side of the connection
        deadline = time.time() + 5
        flow = bridge.tcp_flows[(CLIENT_IP, CLIENT_PORT, "127.0.0.1", http_port)]
        while time.time() < deadline and flow.tunnel_flow.status is None:
            time.sleep(0.05)
        assert flow.tunnel_flow.status == proto.OK

        # the kernel confirms the handshake and sends the request
        bridge.handle_packet(
            ipstack.build_tcp_packet(
                src=CLIENT_IP, dst="127.0.0.1", sport=CLIENT_PORT, dport=http_port,
                seq=KERNEL_ISN + 1, ack=flow.client_isn + 1,
                flags=ipstack.FLAG_ACK | ipstack.FLAG_PSH, window=65535,
                payload=b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            )
        )

        # collect the answer the server sends back
        answer = b""
        deadline = time.time() + 5
        while time.time() < deadline and b"hello from the server" not in answer:
            bridge.pump()
            for packet in bridge.take_output():
                _src, _dst, tcp = parse_one(packet)
                answer += tcp.payload
            time.sleep(0.05)

        assert b"HTTP/1.1 200 OK" in answer
        assert b"hello from the server" in answer
        client.close()
    finally:
        listener.close()


def test_the_bridge_records_the_flow_in_the_inspector(server, master):
    listener, http_port = start_http_server()
    try:
        client = TunnelClient(("127.0.0.1", server.udp.getsockname()[1]), master)
        client.handshake()
        bridge = TcpBridge(client, local_ip=CLIENT_IP)
        client.start_pump(bridge.on_tunnel_data)

        bridge.handle_packet(
            ipstack.build_tcp_packet(
                src=CLIENT_IP, dst="127.0.0.1", sport=CLIENT_PORT, dport=http_port,
                seq=KERNEL_ISN, ack=0, flags=ipstack.FLAG_SYN, window=65535,
            )
        )
        deadline = time.time() + 5
        while time.time() < deadline and not server.inspector.rows():
            time.sleep(0.05)

        rows = server.inspector.rows()
        assert rows, "the flow did not reach the inspector"
        row = rows[0]
        assert row["dst_port"] == str(http_port)
        assert row["src_ip"] == CLIENT_IP
        assert row["src_port"] == str(CLIENT_PORT)
        assert row["proto"] == "TCP"
        client.close()
    finally:
        listener.close()


def test_a_fin_from_the_kernel_still_delivers_the_answer(server, master):
    """The kernel half closes, the destination still has something to say."""
    listener, http_port = start_http_server()
    try:
        client = TunnelClient(("127.0.0.1", server.udp.getsockname()[1]), master)
        client.handshake()
        bridge = TcpBridge(client, local_ip=CLIENT_IP)
        client.start_pump(bridge.on_tunnel_data)

        bridge.handle_packet(
            ipstack.build_tcp_packet(
                src=CLIENT_IP, dst="127.0.0.1", sport=CLIENT_PORT, dport=http_port,
                seq=KERNEL_ISN, ack=0, flags=ipstack.FLAG_SYN, window=65535,
            )
        )
        bridge.take_output()
        flow = bridge.tcp_flows[(CLIENT_IP, CLIENT_PORT, "127.0.0.1", http_port)]

        deadline = time.time() + 5
        while time.time() < deadline and flow.tunnel_flow.status is None:
            time.sleep(0.05)
        assert flow.tunnel_flow.status == proto.OK

        bridge.handle_packet(
            ipstack.build_tcp_packet(
                src=CLIENT_IP, dst="127.0.0.1", sport=CLIENT_PORT, dport=http_port,
                seq=KERNEL_ISN + 1, ack=flow.client_isn + 1,
                flags=ipstack.FLAG_ACK | ipstack.FLAG_PSH, window=65535,
                payload=b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            )
        )
        # the kernel closes its side
        bridge.handle_packet(
            ipstack.build_tcp_packet(
                src=CLIENT_IP, dst="127.0.0.1", sport=CLIENT_PORT, dport=http_port,
                seq=KERNEL_ISN + 1 + 38, ack=flow.client_isn + 1,
                flags=ipstack.FLAG_ACK | ipstack.FLAG_FIN, window=65535,
            )
        )

        answer = b""
        fin_seen = False
        deadline = time.time() + 5
        while time.time() < deadline:
            bridge.pump()
            for packet in bridge.take_output():
                _src, _dst, tcp = parse_one(packet)
                answer += tcp.payload
                if tcp.flags & ipstack.FLAG_FIN:
                    fin_seen = True
            if fin_seen and b"hello from the server" in answer:
                break
            time.sleep(0.05)

        assert b"hello from the server" in answer, "the answer was lost on the half close"
        assert fin_seen, "the kernel was never told that the connection ended"
        client.close()
    finally:
        listener.close()
