"""Flow table and the TCP/UDP relay that sits behind the tunnel.

Each flow is a client requested connection to one destination.  The server
keeps a real socket per flow, which is what finally makes the tunnel useful:
a single device can talk to many destinations at the same time, and every one
of them is accounted for separately in the inspector.
"""

import errno
import socket
import struct
import time

from . import log as logs
from . import protocol as proto
from .inspector import service_name

_BLOCKING_ERRNOS = {
    errno.EAGAIN,
    errno.EWOULDBLOCK,
    errno.EINPROGRESS,
    errno.EALREADY,
    errno.ENOTCONN,
}
_BLOCKING_WINERRORS = {10035, 10037, 10057, 10060}

MAX_SOCKET_READ = 65536

#: The tunnel carries at most 1200 bytes of payload per frame, so the
#: segments of the connection to the destination must stay below that or the
#: destination would have to reassemble them.
TUNNEL_MSS = 1160

#: How much data may pile up between the client and the destination before
#: the server stops reading.  It is the back pressure of the tunnel.
MAX_PENDING = 256 * 1024


def _would_block(exc):
    """True when the error only means "try again later"."""
    if isinstance(exc, BlockingIOError):
        return True
    if isinstance(exc, OSError):
        if exc.errno in _BLOCKING_ERRNOS:
            return True
        if getattr(exc, "winerror", None) in _BLOCKING_WINERRORS:
            return True
    return False


class Flow:
    """One client connection to one destination."""

    def __init__(self, flow_id, session, params):
        self.flow_id = flow_id
        #: flows are unique per client, so the key carries the client address
        self.key = (session.addr, flow_id)
        self.session = session
        self.client_id = session.client_id.hex()
        self.device = session.device
        self.tunnel_src = session.addr[0]
        self.tunnel_src_port = session.addr[1]

        self.proto = params["protocol"]
        self.proto_name = params["proto_name"]
        self.src_ip = params.get("src_ip")
        self.src_port = params.get("src_port")
        self.dst_ip = params.get("dst_ip")
        self.dst_port = params.get("dst_port")
        self.dst_name = params.get("dst_name") or ""
        self.service = service_name(self.dst_port, self.proto_name)

        self.sock = None
        self.state = "connecting"
        self.bytes_up = 0
        self.bytes_down = 0
        self.started_at = time.time()
        self.ended_at = None
        self.note = ""

        self.pending = b""  # bytes still to be written to the internet socket
        self.dgram_buf = b""  # partially received UDP datagram
        self.want_write = False
        self.closing = False  # the client is done sending
        self.close_deadline = None

    @property
    def label(self):
        return "%s -> %s:%s" % (self.source_label, self.dst_ip, self.dst_port)

    @property
    def source_label(self):
        if self.src_ip and self.src_port:
            return "%s:%s" % (self.src_ip, self.src_port)
        if self.src_ip:
            return self.src_ip
        return "%s:%s" % (self.tunnel_src, self.tunnel_src_port)

    def __repr__(self):
        return "<Flow %s %s %s>" % (self.flow_id, self.proto_name, self.label)


class Proxy:
    """Creates, feeds and tears down flows."""

    def __init__(self, server, max_flows=2048):
        self.server = server
        self.flows = {}
        self.max_flows = max_flows

    # -- opening -----------------------------------------------------------
    def open_flow(self, flow_id, session, params):
        """Open a flow.  Returns a protocol status code."""
        key = (session.addr, flow_id)
        if key in self.flows:
            return proto.ERR_EXISTS
        if len(self.flows) >= self.max_flows:
            return proto.ERR_LIMIT
        if params["protocol"] not in (proto.IPPROTO_TCP, proto.IPPROTO_UDP):
            return proto.ERR_UNSUPPORTED

        host = params.get("dst_name") or params.get("dst_ip")
        port = params.get("dst_port")
        if not host or not port:
            return proto.ERR_BAD_REQUEST

        socktype = socket.SOCK_STREAM if params["protocol"] == proto.IPPROTO_TCP else socket.SOCK_DGRAM
        try:
            infos = socket.getaddrinfo(host, port, 0, socktype)
        except socket.gaierror:
            return proto.ERR_RESOLVE
        if not infos:
            return proto.ERR_RESOLVE
        family, _stype, _pnum, _canon, sockaddr = infos[0]

        flow = Flow(flow_id, session, params)
        flow.dst_ip = sockaddr[0]
        if not flow.dst_name:
            flow.dst_name = ""

        try:
            sock = socket.socket(family, socktype)
            bind_host = getattr(self.server, "bind_host", "")
            if bind_host and bind_host not in ("0.0.0.0", "::", ""):
                # Use the same address as the tunnel itself.  Otherwise the
                # kernel picks the source address by the route it finds, and
                # that route may lead straight back into the tunnel.
                try:
                    sock.bind((bind_host, 0))
                except OSError:
                    pass  # wrong family, the route has to do
            sock.setblocking(False)
            if params["protocol"] == proto.IPPROTO_TCP:
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, TUNNEL_MSS)
                except OSError:
                    pass  # not supported everywhere
                result = sock.connect_ex(sockaddr)
                if result not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY):
                    sock.close()
                    return proto.ERR_REFUSED if result in (
                        errno.ECONNREFUSED,
                        getattr(errno, "WSAECONNREFUSED", 10061),
                    ) else proto.ERR_CONNECT
            else:
                sock.connect(sockaddr)
        except socket.gaierror:
            return proto.ERR_RESOLVE
        except OSError as exc:
            logs.error("Cannot open %s: %s" % (flow.label, exc))
            return proto.ERR_CONNECT

        flow.sock = sock
        self.flows[key] = flow
        session.flow_ids.add(flow_id)
        self.server.attach_socket(flow)
        if params["protocol"] == proto.IPPROTO_TCP:
            # The connect is still in progress: watch for writability so the
            # OPEN_OK is sent as soon as the handshake really finished.
            self.server.want_write(flow)
        self.server.inspector.upsert(flow)

        logs.tunnel(
            "%s -> %s:%s (%s/%s)"
            % (
                flow.source_label,
                flow.dst_ip,
                flow.dst_port,
                flow.proto_name,
                flow.service,
            )
        )

        if params["protocol"] == proto.IPPROTO_UDP:
            # A UDP "connection" is ready straight away.
            flow.state = "active"
        # For TCP the OPEN_OK is only sent once the handshake really finished.
        return proto.OK if params["protocol"] == proto.IPPROTO_UDP else None

    # -- client -> internet ------------------------------------------------
    def on_data(self, flow, payload, flags=0):
        if flow.sock is None or flow.state in ("closed", "error"):
            return
        if flow.proto == proto.IPPROTO_UDP:
            datagram = self._collect_datagram(flow, payload, flags)
            if datagram is None:
                return
            try:
                sent = flow.sock.send(datagram)
            except (BlockingIOError, InterruptedError):
                sent = 0
            except OSError as exc:
                if not _would_block(exc):
                    self.close_flow(flow, proto.CLOSE_ERROR, "error", "send failed: %s" % exc)
                    return
                sent = 0
            if sent:
                flow.bytes_up += sent
                logs.detail("Payload sent to %s:%s (%d bytes)" % (flow.dst_ip, flow.dst_port, sent))
                self.server.inspector.upsert(flow)
            return

        flow.pending += payload
        self._flush_to_target(flow)

    def _collect_datagram(self, flow, payload, flags):
        if not flags & proto.FLAG_DATAGRAM:
            return payload
        if len(payload) < 2:
            return None
        total = struct.unpack("!H", payload[:2])[0]
        flow.dgram_buf += payload[2:]
        if len(flow.dgram_buf) < total:
            return None
        datagram = flow.dgram_buf[:total]
        flow.dgram_buf = b""
        return datagram

    def _flush_to_target(self, flow):
        if not flow.pending or flow.sock is None:
            return
        try:
            sent = flow.sock.send(flow.pending)
        except (BlockingIOError, InterruptedError):
            sent = 0
        except OSError as exc:
            if not _would_block(exc):
                self.close_flow(flow, proto.CLOSE_ERROR, "error", "send failed: %s" % exc)
                return
            sent = 0
        if sent:
            flow.pending = flow.pending[sent:]
            flow.bytes_up += sent
            logs.detail("Payload sent to %s:%s (%d bytes)" % (flow.dst_ip, flow.dst_port, sent))
            self.server.inspector.upsert(flow)
            if flow.pending and len(flow.pending) < MAX_PENDING:
                self.server.want_read(flow)
        if flow.pending:
            self.server.want_write(flow)

    # -- internet -> client ------------------------------------------------
    def on_socket_readable(self, flow):
        if flow.sock is None:
            return
        if len(flow.pending) >= MAX_PENDING:
            # the client is not keeping up, stop reading until the buffer
            # drained.  This is the back pressure of the tunnel.
            self.server.clear_read(flow)
            return
        try:
            data = flow.sock.recv(MAX_SOCKET_READ)
        except (BlockingIOError, InterruptedError):
            return
        except OSError as exc:
            if _would_block(exc):
                return
            self.close_flow(flow, proto.CLOSE_RESET, "error", "recv failed: %s" % exc)
            return

        if not data:
            self.close_flow(flow, proto.CLOSE_NORMAL, "closed", "peer closed the connection")
            return

        flow.bytes_down += len(data)
        logs.response("RESPONSE from Internet (%d bytes)" % len(data))
        self._send_to_client(flow, data)
        self.server.inspector.upsert(flow)

    def _send_to_client(self, flow, data):
        if flow.proto == proto.IPPROTO_UDP:
            total = len(data)
            offset = 0
            while offset < total:
                chunk = data[offset:offset + proto.MAX_DATA]
                payload = struct.pack("!H", total) + chunk
                self.server.send_frame(
                    flow.session, flow.flow_id, proto.DATA, payload, proto.FLAG_DATAGRAM
                )
                offset += len(chunk)
            return
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + proto.MAX_DATA]
            self.server.send_frame(flow.session, flow.flow_id, proto.DATA, chunk)
            offset += len(chunk)

    # -- socket lifecycle --------------------------------------------------
    def on_socket_writable(self, flow):
        if flow.sock is None:
            return
        if flow.state == "connecting":
            error = flow.sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if error:
                logs.error(
                    "Connection to %s:%s failed: %s"
                    % (flow.dst_ip, flow.dst_port, errno.errorcode.get(error, error))
                )
                self.server.send_frame(
                    flow.session, flow.flow_id, proto.OPEN_OK, bytes([proto.ERR_CONNECT])
                )
                self.close_flow(flow, proto.CLOSE_ERROR, "error", "connect failed")
                return
            flow.state = "active"
            logs.ok("Handshake complete! Data sent to internet.")
            self.server.send_frame(
                flow.session, flow.flow_id, proto.OPEN_OK, bytes([proto.OK])
            )
            self.server.inspector.upsert(flow)
        self._flush_to_target(flow)
        if not flow.pending and flow.state != "connecting":
            self.server.clear_write(flow)

    def on_close(self, flow, payload=b""):
        reason = payload[0] if payload else proto.CLOSE_NORMAL
        if flow.proto == proto.IPPROTO_TCP and flow.sock is not None and not flow.closing:
            # The client will not send anything more, but the destination may
            # still have data for us.  Half close and wait for the other side.
            try:
                flow.sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            flow.closing = True
            flow.close_deadline = time.time() + 30
            return
        self.close_flow(flow, reason, "closed")

    def expire_closing(self):
        """Close the flows whose destination never said goodbye."""
        now = time.time()
        for flow in list(self.flows.values()):
            if flow.close_deadline is not None and now > flow.close_deadline:
                self.close_flow(flow, proto.CLOSE_TIMEOUT, "closed", "the destination hung up late")

    def close_flow(self, flow, reason=proto.CLOSE_NORMAL, state="closed", note=""):
        if flow.key not in self.flows:
            return
        if note:
            flow.note = note
        flow.state = state
        flow.ended_at = time.time()
        self.server.detach_socket(flow)
        if flow.sock is not None:
            try:
                flow.sock.close()
            except OSError:
                pass
            flow.sock = None
        self.flows.pop(flow.key, None)
        flow.session.flow_ids.discard(flow.flow_id)
        self.server.inspector.upsert(flow)
        self.server.send_frame(flow.session, flow.flow_id, proto.CLOSE, bytes([reason]))
        logs.info(
            "Closing session for %s (%s, up %d B, down %d B)"
            % (
                flow.source_label,
                proto.close_name(reason),
                flow.bytes_up,
                flow.bytes_down,
            )
        )

    def close_all(self, reason=proto.CLOSE_SHUTDOWN):
        for flow in list(self.flows.values()):
            self.close_flow(flow, reason, "closed", "server shutdown")
