"""The TCP bridge: it lets the local kernel talk to the server.

The kernel of the device believes it is talking to the internet directly, and
that is exactly what the bridge arranges - but the packets travel through the
tunnel instead.

The bridge **terminates** the TCP connection for the local kernel and
**proxies** it to the server, which terminates it for the destination.  Two
connections are stitched together:

    kernel                    bridge                    server
      |                          |                          |
      |--- SYN (seq=K) --------->| open flow -------------->|
      |<-- SYN-ACK (seq=S,ack=K+1)                          |
      |--- ACK ---------------->|                          |
      |--- PSH,ACK (data) ----->| DATA (payload only) ---->|--> destination
      |                          |<-- DATA (payload) ------|<-- destination
      |<-- ACK,PSH (data) ------|                          |

Only the payload crosses the tunnel.  The bridge keeps two sequence spaces
apart: ``K`` belongs to the kernel and is tracked so the acknowledgements
the bridge sends back are correct, ``S`` belongs to the bridge itself and is
invented here.  The server never sees either of them.

The bridge is deliberately independent of the TUN device: it consumes and
produces plain IP packets, so it can be driven by a real TUN, by a test
harness or by a script.
"""

import random
import struct
import threading
from collections import deque

from . import ipstack
from server import protocol as proto


class TcpFlow:
    """One TCP connection between the kernel and the server."""

    def __init__(self, key, kernel_isn, client_isn, tunnel_flow):
        self.key = key
        self.client_ip, self.client_port, self.server_ip, self.server_port = key

        self.kernel_isn = kernel_isn
        self.kernel_seq = kernel_isn + 1  # the next byte we expect
        self.client_isn = client_isn
        self.client_seq = client_isn + 1  # the next byte we send
        # until the kernel answers the SYN-ACK we assume it arrived, so it
        # confirmed client_isn + 1
        self.kernel_ack = client_isn + 1
        self.kernel_window = 65535  # what the kernel can still accept

        self.tunnel_flow = tunnel_flow
        self.outbuf = bytearray()  # data the kernel's window did not allow
        self.fin_sent = False
        self.fin_received = False
        self.reset_sent = False
        self.closed = False

    def __repr__(self):
        return "<TcpFlow %s:%d -> %s:%d>" % (
            self.client_ip, self.client_port, self.server_ip, self.server_port
        )


class UdpFlow:
    """One UDP association between the kernel and the server."""

    def __init__(self, key, tunnel_flow):
        self.key = key
        self.client_ip, self.client_port, self.server_ip, self.server_port = key
        self.tunnel_flow = tunnel_flow
        self.closed = False

    def __repr__(self):
        return "<UdpFlow %s:%d -> %s:%d>" % (
            self.client_ip, self.client_port, self.server_ip, self.server_port
        )


class TcpBridge:
    """Turns the packets of the kernel into tunnel flows and back."""

    def __init__(self, tunnel, local_ip="10.8.0.2", mss=1160, window=65535,
                 resolve=False, dns_server=None, verbose=False):
        self.tunnel = tunnel
        self.local_ip = local_ip
        self.mss = mss
        self.window = window
        self.resolve = resolve
        self.dns_server = dns_server
        self.verbose = verbose

        self.tcp_flows = {}
        self.udp_flows = {}
        self._by_tunnel_id = {}
        self._out = []
        self._incoming = deque()
        self._lock = threading.Lock()

    # -- the kernel side ---------------------------------------------------
    def handle_packet(self, data):
        """Feed one IP packet that came from the kernel."""
        try:
            src, dst, protocol, payload = ipstack.parse_ipv4(data)
        except ValueError:
            return
        if protocol == ipstack.PROTO_TCP:
            self._handle_tcp(src, dst, payload)
        elif protocol == ipstack.PROTO_UDP:
            self._handle_udp(src, dst, payload)

    def take_output(self):
        """Return the packets that have to be written back to the kernel."""
        with self._lock:
            packets = self._out
            self._out = []
        return packets

    def _emit(self, packet):
        with self._lock:
            self._out.append(packet)

    # -- TCP ---------------------------------------------------------------
    def _handle_tcp(self, src, dst, payload):
        try:
            tcp = ipstack.parse_tcp(payload)
        except ValueError:
            return

        key = (src, tcp.sport, dst, tcp.dport)
        flow = self.tcp_flows.get(key)

        if flow is None:
            if not tcp.flags & ipstack.FLAG_SYN:
                # the flow is not known, so the packet is refused
                self._emit(self._reset(src, dst, tcp))
                return
            flow = self._open_tcp(key, src, dst, tcp)
            self._send_synack(flow)
            return

        if tcp.flags & ipstack.FLAG_RST:
            self._close_tcp(flow)
            return

        if tcp.flags & ipstack.FLAG_SYN:
            # a retransmitted SYN: answer with the same numbers
            self._send_synack(flow)
            return

        if tcp.flags & ipstack.FLAG_ACK:
            flow.kernel_ack = tcp.ack
            flow.kernel_window = tcp.window if tcp.window else 1
            self._flush_outbuf(flow)

        if tcp.payload:
            self._payload_to_tunnel(flow, tcp)

        if tcp.flags & ipstack.FLAG_FIN:
            self._fin_from_kernel(flow, tcp)

    def _open_tcp(self, key, src, dst, tcp):
        tunnel_flow = self.tunnel.open_flow(
            dst,
            tcp.dport,
            protocol=ipstack.PROTO_TCP,
            src_ip=src,
            src_port=tcp.sport,
            resolve=self.resolve,
        )
        flow = TcpFlow(key, tcp.seq, random.getrandbits(32), tunnel_flow)
        self.tcp_flows[key] = flow
        self._by_tunnel_id[tunnel_flow.flow_id] = flow
        if self.verbose:
            print("[+] tcp %s:%d -> %s:%d" % (src, tcp.sport, dst, tcp.dport))
        return flow

    def _payload_to_tunnel(self, flow, tcp):
        if tcp.seq != flow.kernel_seq:
            # out of order or a duplicate: confirm what we have, the kernel
            # will send the rest again
            self._send_ack(flow)
            return
        flow.kernel_seq += len(tcp.payload)
        self.tunnel.send(flow.tunnel_flow.flow_id, tcp.payload)
        self._send_ack(flow)

    def _fin_from_kernel(self, flow, tcp):
        if tcp.seq == flow.kernel_seq:
            flow.kernel_seq += 1
        flow.fin_received = True
        self.tunnel.close_flow(flow.tunnel_flow.flow_id)
        self._send_ack(flow)

    def _reply(self, flow, seq, ack, flags, payload=b"", options=b""):
        return ipstack.build_tcp_packet(
            src=flow.server_ip,
            dst=flow.client_ip,
            sport=flow.server_port,
            dport=flow.client_port,
            seq=seq,
            ack=ack,
            flags=flags,
            window=self.window,
            payload=payload,
            options=options,
        )

    def _send_synack(self, flow):
        self._emit(
            self._reply(
                flow,
                flow.client_isn,
                flow.kernel_seq,
                ipstack.FLAG_SYN | ipstack.FLAG_ACK,
                options=ipstack.mss_option(self.mss),
            )
        )

    def _send_ack(self, flow):
        self._emit(
            self._reply(flow, flow.client_seq, flow.kernel_seq, ipstack.FLAG_ACK)
        )

    def _send_fin(self, flow):
        self._emit(
            self._reply(
                flow, flow.client_seq, flow.kernel_seq,
                ipstack.FLAG_ACK | ipstack.FLAG_FIN,
            )
        )
        flow.fin_sent = True

    def _reset(self, src, dst, tcp):
        """A RST for a flow the bridge does not know."""
        return ipstack.build_tcp_packet(
            src=dst,
            dst=src,
            sport=tcp.dport,
            dport=tcp.sport,
            seq=0,
            ack=tcp.seq + len(tcp.payload) + (1 if tcp.flags & ipstack.FLAG_SYN else 0),
            flags=ipstack.FLAG_RST | ipstack.FLAG_ACK,
            window=0,
        )

    def _close_tcp(self, flow):
        flow.closed = True
        self.tcp_flows.pop(flow.key, None)
        self._by_tunnel_id.pop(flow.tunnel_flow.flow_id, None)
        try:
            self.tunnel.close_flow(flow.tunnel_flow.flow_id)
        except Exception:
            pass

    # -- UDP ---------------------------------------------------------------
    def _handle_udp(self, src, dst, payload):
        try:
            sport, dport, data = ipstack.parse_udp(payload)
        except ValueError:
            return

        # The resolver of the network is usually a machine of the local
        # network, the server could not reach it.  Send the queries to a
        # public resolver instead, through the tunnel.
        if self.dns_server and dport == 53:
            dst = self.dns_server

        key = (src, sport, dst, dport)
        flow = self.udp_flows.get(key)
        if flow is None:
            tunnel_flow = self.tunnel.open_flow(
                dst,
                dport,
                protocol=ipstack.PROTO_UDP,
                src_ip=src,
                src_port=sport,
                resolve=self.resolve,
            )
            flow = UdpFlow(key, tunnel_flow)
            self.udp_flows[key] = flow
            self._by_tunnel_id[tunnel_flow.flow_id] = flow
            if self.verbose:
                print("[+] udp %s:%d -> %s:%d" % (src, sport, dst, dport))
        self.tunnel.send(flow.tunnel_flow.flow_id, data, datagram=True)

    def _udp_to_kernel(self, flow, data):
        self._emit(
            ipstack.build_udp_packet(
                src=flow.server_ip,
                dst=flow.client_ip,
                sport=flow.server_port,
                dport=flow.client_port,
                payload=data,
            )
        )

    # -- the tunnel side ---------------------------------------------------
    def on_tunnel_data(self, tunnel_flow, data, is_datagram=False):
        """Called by the tunnel client when a flow received something."""
        with self._lock:
            self._incoming.append((tunnel_flow.flow_id, data, is_datagram))

    def pump(self):
        """Move what came back from the tunnel towards the kernel."""
        with self._lock:
            items = list(self._incoming)
            self._incoming.clear()

        for flow_id, data, is_datagram in items:
            flow = self._by_tunnel_id.get(flow_id)
            if flow is None:
                continue
            if isinstance(flow, UdpFlow):
                self._udp_to_kernel(flow, data)
                continue
            self._data_to_kernel(flow, data)

        # flows the server closed, or could not open
        for flow in list(self.tcp_flows.values()):
            tunnel_flow = flow.tunnel_flow
            status = tunnel_flow.status
            if status is not None and status != proto.OK:
                if not flow.reset_sent:
                    flow.reset_sent = True
                    self._emit(
                        self._reply(
                            flow, flow.client_seq, flow.kernel_seq,
                            ipstack.FLAG_RST | ipstack.FLAG_ACK,
                        )
                    )
                continue
            if tunnel_flow.closed and not flow.fin_sent:
                self._send_fin(flow)

    def _data_to_kernel(self, flow, data):
        space = flow.kernel_window - (flow.client_seq - flow.kernel_ack)
        if space <= 0:
            # the kernel is not accepting anything right now
            flow.outbuf += data
            return
        take = min(space, len(data))
        chunk, rest = data[:take], data[take:]
        if chunk:
            self._emit(
                self._reply(
                    flow, flow.client_seq, flow.kernel_seq,
                    ipstack.FLAG_ACK | ipstack.FLAG_PSH, payload=chunk,
                )
            )
            flow.client_seq += len(chunk)
        if rest:
            flow.outbuf += rest

    def _flush_outbuf(self, flow):
        if not flow.outbuf:
            return
        space = flow.kernel_window - (flow.client_seq - flow.kernel_ack)
        if space <= 0:
            return
        take = min(space, len(flow.outbuf))
        chunk = bytes(flow.outbuf[:take])
        del flow.outbuf[:take]
        if chunk:
            self._emit(
                self._reply(
                    flow, flow.client_seq, flow.kernel_seq,
                    ipstack.FLAG_ACK | ipstack.FLAG_PSH, payload=chunk,
                )
            )
            flow.client_seq += len(chunk)
