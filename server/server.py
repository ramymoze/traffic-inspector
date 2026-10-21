"""The traffic-inspector tunnel server.

Run it with::

    python listeningServer.py --port 5555 --csv traffic.csv

The server listens for encrypted UDP datagrams, terminates the tunnel, relays
the traffic it carries to the real internet and records what it saw in a CSV
file and in the terminal.
"""

import argparse
import errno
import hmac
import secrets
import selectors
import socket
import struct
import sys
import time
from collections import deque

from . import log as logs
from . import protocol as proto
from .crypto import (
    CLIENT_ID_LEN,
    CryptoError,
    SessionCrypto,
    ack_proof,
    derive_session_key,
    hello_proof,
    load_master_key,
    seal_with_master,
    unseal_with_master,
)
from .inspector import Inspector
from .proxy import Proxy, _would_block

NONCE_LEN = 8


class ClientSession:
    """One connected client."""

    def __init__(self, addr, client_id, server_id, key, device=""):
        self.addr = addr
        self.client_id = client_id
        self.server_id = server_id
        #: the name the client gave itself, shown in the inspector
        self.device = device
        self.crypto = SessionCrypto(key, send_id=server_id, recv_id=client_id)
        self.created = time.time()
        self.last_seen = time.time()
        self.flow_ids = set()

    def touch(self):
        self.last_seen = time.time()

    def __repr__(self):
        return "<ClientSession %s:%s>" % self.addr


class TunnelServer:
    def __init__(
        self,
        host="0.0.0.0",
        port=5555,
        csv_path="traffic.csv",
        key_file=None,
        level="verbose",
        max_flows=2048,
        session_timeout=300.0,
    ):
        logs.configure(level)
        self.host = host
        self.port = port
        #: the address the tunnel listens on.  The flows are bound to it as
        #: well, so the traffic of the server does not accidentally take a
        #: route that leads back into the tunnel.
        self.bind_host = host
        self.master = load_master_key(key_file)
        self.inspector = Inspector(csv_path)
        self.proxy = Proxy(self, max_flows=max_flows)
        self.session_timeout = session_timeout

        self.sessions = {}
        self.outbox = deque()
        self.selector = selectors.DefaultSelector()
        self.running = True

        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp.bind((host, port))
        self.udp.setblocking(False)
        self.selector.register(self.udp, selectors.EVENT_READ, ("udp", None))

    # -- main loop ---------------------------------------------------------
    def run(self):
        logs.info("Tunnel is active at %s:%d" % (self.host, self.port))
        logs.info("Monitoring Tunnel and Internet sessions...")
        logs.info("Inspector writing to %s" % self.inspector.path)
        try:
            while self.running:
                events = self.selector.select(timeout=0.2)
                for key, mask in events:
                    kind, flow = key.data
                    if kind == "udp":
                        if mask & selectors.EVENT_READ:
                            self._read_datagram()
                        if mask & selectors.EVENT_WRITE:
                            self._flush_outbox()
                    else:
                        if mask & selectors.EVENT_READ:
                            self.proxy.on_socket_readable(flow)
                        if mask & selectors.EVENT_WRITE:
                            self.proxy.on_socket_writable(flow)
                self.inspector.maybe_write()
                self._expire_sessions()
                self.proxy.expire_closing()
        except KeyboardInterrupt:
            logs.warn("Shutdown signal received. Closing all sockets.")
        except Exception as exc:  # pragma: no cover - safety net
            logs.error("CRITICAL Server Error: %s" % exc)
        finally:
            self.shutdown()

    def shutdown(self):
        self.running = False
        try:
            self.proxy.close_all()
        except Exception:
            pass
        for session in list(self.sessions.values()):
            self.sessions.pop(session.addr, None)
        try:
            self.selector.unregister(self.udp)
        except (KeyError, ValueError):
            pass
        try:
            self.udp.close()
        except OSError:
            pass
        try:
            self.inspector.maybe_write(force=True)
        except Exception:
            pass
        logs.info("Server is Down.")

    # -- datagram handling -------------------------------------------------
    def _read_datagram(self):
        try:
            data, addr = self.udp.recvfrom(65535)
        except (BlockingIOError, InterruptedError):
            return
        except OSError as exc:
            # On Windows a datagram sent to a client that vanished comes back
            # as a connection reset.  That is normal, not an error.
            if exc.errno in (errno.ECONNRESET, errno.ECONNREFUSED) or getattr(
                exc, "winerror", None
            ) in (10054, 10061):
                logs.log("!", "Client is gone (%s)" % exc, logs.VERBOSE, "warn")
                return
            logs.error("Socket error: %s" % exc)
            return

        if len(data) > proto.MAX_FRAME:
            logs.error("Inbound Error: oversized frame from %s (%d bytes)" % (addr[0], len(data)))
            return

        try:
            ftype, flags, flow_id, payload = self._decrypt(data, addr)
        except (CryptoError, proto.ProtocolError) as exc:
            logs.error("Inbound Error: %s" % exc)
            return

        try:
            self._dispatch(addr, ftype, flags, flow_id, payload)
        except (CryptoError, proto.ProtocolError) as exc:
            logs.error("Inbound Error: %s" % exc)

    def _decrypt(self, data, addr):
        session = self.sessions.get(addr)
        if session is not None:
            try:
                opened = session.crypto.decrypt(data)
            except CryptoError:
                opened = None
            if opened is not None:
                header, payload = opened
                parsed = proto.parse_header(header)
                if len(payload) != parsed["length"]:
                    raise proto.ProtocolError("payload length mismatch")
                session.touch()
                return parsed["type"], parsed["flags"], parsed["flow_id"], payload
            # a frame of an older session, it may be a fresh handshake
            session = None
            self._describe(addr, data, "not for this session")

        # No usable session: this must be a HELLO sealed with the master key.
        try:
            header, payload = unseal_with_master(self.master, data)
        except CryptoError:
            self._describe(addr, data, "not for this session")
            raise CryptoError("authentication failed (MAC check failed)")
        parsed = proto.parse_header(header)
        if parsed["type"] != proto.HELLO:
            raise CryptoError("expected a HELLO frame")
        self._create_session(addr, payload)
        return parsed["type"], parsed["flags"], parsed["flow_id"], payload

    def _describe(self, addr, data, why):
        """Say what a frame that was refused looked like."""
        if len(data) < 10:
            logs.error("Inbound Error: %s (%d bytes) from %s" % (why, len(data), addr[0]))
            return
        version, ftype, flags, _rsv, length, flow_id = struct.unpack("!BBBBHI", data[:10])
        session = self.sessions.get(addr)
        expected = session.crypto.recv_id.hex() if session else "none"
        actual = data[10:18].hex() if len(data) >= 18 else "?"
        logs.error(
            "Inbound Error: %s from %s (%s, flow %d, %d bytes, session %s, wanted %s)"
            % (why, addr[0], proto.type_name(ftype), flow_id, length, actual, expected)
        )

    def _create_session(self, addr, payload):
        client_id, client_nonce, proof, device = proto.parse_hello(payload)
        if not hmac.compare_digest(hello_proof(self.master, client_id, client_nonce), proof):
            raise CryptoError("invalid HELLO proof")

        server_id = secrets.token_bytes(CLIENT_ID_LEN)
        server_nonce = secrets.token_bytes(NONCE_LEN)
        key = derive_session_key(self.master, client_id, server_id, client_nonce, server_nonce)

        # a client that comes back after a restart replaces its old session,
        # the flows of the old one are dead
        old = self.sessions.get(addr)
        if old is not None:
            for flow_id in list(old.flow_ids):
                flow = self.proxy.flows.get((addr, flow_id))
                if flow is not None:
                    self.proxy.close_flow(flow, proto.CLOSE_TIMEOUT, "closed",
                                         "the client came back")

        session = ClientSession(addr, client_id, server_id, key, device=device)
        self.sessions[addr] = session

        ack = (
            server_id
            + server_nonce
            + ack_proof(self.master, client_id, server_id, client_nonce, server_nonce)
        )
        header = proto.build_header(proto.HELLO_ACK, 0, len(ack))
        self._send_datagram(addr, seal_with_master(self.master, header, ack))
        logs.ok(
            "Client connected: %s:%d (session %s%s)"
            % (addr[0], addr[1], client_id.hex(), ", device %s" % device if device else "")
        )

    def _dispatch(self, addr, ftype, flags, flow_id, payload):
        session = self.sessions.get(addr)
        if session is None:
            return

        if ftype == proto.HELLO:
            return
        if ftype == proto.OPEN:
            self._handle_open(session, flow_id, payload)
        elif ftype == proto.DATA:
            flow = self.proxy.flows.get((addr, flow_id))
            if flow is not None and flow.session is session:
                self.proxy.on_data(flow, payload, flags)
        elif ftype == proto.CLOSE:
            flow = self.proxy.flows.get((addr, flow_id))
            if flow is not None and flow.session is session:
                self.proxy.on_close(flow, payload)
        elif ftype == proto.PING:
            self.send_frame(session, flow_id, proto.PONG)
        else:
            raise proto.ProtocolError("unexpected frame type %s" % proto.type_name(ftype))

    def _handle_open(self, session, flow_id, payload):
        try:
            params = proto.decode_open(payload)
        except proto.ProtocolError as exc:
            logs.error("Bad OPEN frame: %s" % exc)
            self.send_frame(session, flow_id, proto.OPEN_OK, bytes([proto.ERR_BAD_REQUEST]))
            return
        status = self.proxy.open_flow(flow_id, session, params)
        if status is None:
            return  # TCP: the answer is sent when the handshake completes
        if status != proto.OK:
            logs.error(
                "Cannot open %s:%s - %s"
                % (params.get("dst_name") or params.get("dst_ip"), params.get("dst_port"),
                   proto.status_name(status))
            )
        self.send_frame(session, flow_id, proto.OPEN_OK, bytes([status]))

    # -- sending ------------------------------------------------------------
    def send_frame(self, session, flow_id, ftype, payload=b"", flags=0):
        header = proto.build_header(ftype, flow_id, len(payload), flags)
        wire = session.crypto.encrypt(header, payload)
        self._send_datagram(session.addr, wire)

    def _send_datagram(self, addr, data):
        try:
            self.udp.sendto(data, addr)
        except (BlockingIOError, InterruptedError):
            self.outbox.append((addr, data))
            self._want_udp_write(True)
        except OSError as exc:
            if _would_block(exc):
                self.outbox.append((addr, data))
                self._want_udp_write(True)
            else:
                logs.error("Cannot send to %s: %s" % (addr, exc))

    def _flush_outbox(self):
        while self.outbox:
            addr, data = self.outbox[0]
            try:
                self.udp.sendto(data, addr)
            except (BlockingIOError, InterruptedError):
                return
            except OSError as exc:
                if _would_block(exc):
                    return
                self.outbox.popleft()
                logs.error("Cannot send to %s: %s" % (addr, exc))
                continue
            self.outbox.popleft()
        self._want_udp_write(False)

    def _want_udp_write(self, wanted):
        try:
            key = self.selector.get_key(self.udp)
        except KeyError:
            return
        events = key.events | selectors.EVENT_WRITE if wanted else key.events & ~selectors.EVENT_WRITE
        if events != key.events:
            self.selector.modify(self.udp, events, key.data)

    # -- selector helpers ---------------------------------------------------
    def attach_socket(self, flow):
        try:
            self.selector.register(flow.sock, selectors.EVENT_READ, ("flow", flow))
        except (KeyError, ValueError):
            pass

    def detach_socket(self, flow):
        if flow.sock is None:
            return
        try:
            self.selector.unregister(flow.sock)
        except (KeyError, ValueError):
            pass

    def want_write(self, flow):
        if flow.sock is None:
            return
        try:
            key = self.selector.get_key(flow.sock)
        except KeyError:
            return
        if not key.events & selectors.EVENT_WRITE:
            self.selector.modify(
                flow.sock, key.events | selectors.EVENT_WRITE, key.data
            )

    def want_read(self, flow):
        if flow.sock is None:
            return
        try:
            key = self.selector.get_key(flow.sock)
        except KeyError:
            return
        if not key.events & selectors.EVENT_READ:
            self.selector.modify(
                flow.sock, key.events | selectors.EVENT_READ, key.data
            )

    def clear_read(self, flow):
        if flow.sock is None:
            return
        try:
            key = self.selector.get_key(flow.sock)
        except KeyError:
            return
        if key.events & selectors.EVENT_READ:
            self.selector.modify(
                flow.sock, key.events & ~selectors.EVENT_READ, key.data
            )

    def clear_write(self, flow):
        if flow.sock is None:
            return
        try:
            key = self.selector.get_key(flow.sock)
        except KeyError:
            return
        if key.events & selectors.EVENT_WRITE:
            self.selector.modify(
                flow.sock, key.events & ~selectors.EVENT_WRITE, key.data
            )

    # -- housekeeping -------------------------------------------------------
    def _expire_sessions(self):
        now = time.time()
        for addr, session in list(self.sessions.items()):
            if now - session.last_seen < self.session_timeout:
                continue
            for flow_id in list(session.flow_ids):
                flow = self.proxy.flows.get((addr, flow_id))
                if flow is not None:
                    self.proxy.close_flow(flow, proto.CLOSE_TIMEOUT, "closed", "session timed out")
            self.sessions.pop(addr, None)
            logs.info("Session %s timed out" % addr[0])


def main(argv=None):
    parser = argparse.ArgumentParser(description="traffic-inspector tunnel server")
    parser.add_argument("--host", default="0.0.0.0", help="address to bind (default 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5555, help="UDP port (default 5555)")
    parser.add_argument("--csv", default="traffic.csv", help="CSV file to write (default traffic.csv)")
    parser.add_argument("--key-file", default=None, help="file holding the master key (default .env)")
    parser.add_argument(
        "--level",
        default="verbose",
        choices=["quiet", "normal", "verbose"],
        help="terminal verbosity (default verbose)",
    )
    parser.add_argument("--max-flows", type=int, default=2048, help="maximum simultaneous flows")
    parser.add_argument(
        "--session-timeout",
        type=float,
        default=300.0,
        help="drop a client after this many idle seconds (default 300)",
    )
    args = parser.parse_args(argv)

    try:
        server = TunnelServer(
            host=args.host,
            port=args.port,
            csv_path=args.csv,
            key_file=args.key_file,
            level=args.level,
            max_flows=args.max_flows,
            session_timeout=args.session_timeout,
        )
    except CryptoError as exc:
        print("Cannot start the server: %s" % exc, file=sys.stderr)
        return 1

    server.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
