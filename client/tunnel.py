"""Client side of the traffic-inspector tunnel.

This module holds the part of the client that talks to the server: the
handshake, the flow bookkeeping and the frame codec.  It is shared by the
stub client (``testing.py``), by the SOCKS5 proxy (``client.socks``) and,
later on, by the TUN based clients that will live in this package.
"""

import platform
import secrets
import socket
import struct
import threading
import time

from server import protocol as proto
from server.crypto import (
    CLIENT_ID_LEN,
    CryptoError,
    SessionCrypto,
    ack_proof,
    derive_session_key,
    hello_proof,
    seal_with_master,
    unseal_with_master,
)

NONCE_LEN = 8
PROOF_LEN = 16


class TunnelError(Exception):
    """Raised when the tunnel misbehaves."""


def default_device():
    """A name for this device, so the server can tell them apart.

    The server sees the name in the inspector, which is what makes it
    possible to follow one device over time.  It is only a name, nothing
    else is sent.
    """
    try:
        host = socket.gethostname()
    except OSError:
        host = "unknown"
    system = (platform.system() or "unknown").lower()
    return ("%s-%s" % (system, host))[:60]


class RemoteFlow:
    """A flow opened on the server.

    The flow is a byte stream: the data that comes back from the server is
    buffered here and read with :meth:`read`.  It is safe to use from several
    threads.
    """

    def __init__(self, flow_id, dst_host, dst_port, protocol=proto.IPPROTO_TCP):
        self.flow_id = flow_id
        self.dst_host = dst_host
        self.dst_port = dst_port
        self.protocol = protocol
        self.status = None  # filled in when the server answers OPEN_OK
        self.closed = False
        self.bytes_in = 0
        self.bytes_out = 0
        self.opened_at = time.time()
        self._condition = threading.Condition()
        self._stream = bytearray()
        self._datagrams = []
        self.dgram_buf = b""  # partially received datagram
        self._eof = False

    # -- receiving ---------------------------------------------------------
    def append(self, data, is_datagram=False):
        with self._condition:
            if is_datagram:
                self._datagrams.append(data)
            else:
                self._stream += data
            self._condition.notify_all()

    def mark_eof(self):
        with self._condition:
            self._eof = True
            self._condition.notify_all()

    def read(self, timeout=None, max_bytes=65536):
        """Return the bytes received so far.  An empty result means the flow
        ended (or the timeout expired)."""
        deadline = None if timeout is None else time.time() + timeout
        with self._condition:
            while not self._stream and not self._eof:
                wait = 0.5
                if deadline is not None:
                    wait = deadline - time.time()
                    if wait <= 0:
                        break
                self._condition.wait(wait)
            if not self._stream:
                return b""
            data = bytes(self._stream[:max_bytes])
            del self._stream[:max_bytes]
            return data

    def datagram(self, timeout=None):
        """Return one complete UDP datagram, or ``None``."""
        deadline = None if timeout is None else time.time() + timeout
        with self._condition:
            while not self._datagrams and not self._eof:
                wait = 0.5
                if deadline is not None:
                    wait = deadline - time.time()
                    if wait <= 0:
                        break
                self._condition.wait(wait)
            if not self._datagrams:
                return None
            return self._datagrams.pop(0)

    def wait_status(self, timeout=None):
        """Wait for the server to answer the OPEN.  Returns the status."""
        deadline = None if timeout is None else time.time() + timeout
        with self._condition:
            while self.status is None:
                wait = 0.5
                if deadline is not None:
                    wait = deadline - time.time()
                    if wait <= 0:
                        break
                self._condition.wait(wait)
            return self.status

    @property
    def buffer(self):
        with self._condition:
            return bytes(self._stream)

    def __repr__(self):
        return "<RemoteFlow %d %s:%s>" % (self.flow_id, self.dst_host, self.dst_port)


class TunnelClient:
    """A UDP client for the tunnel server."""

    def __init__(self, server_addr, master_key, timeout=10.0, device=None):
        self.server_addr = server_addr
        self.master = master_key
        self.timeout = timeout
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)
        self.client_id = secrets.token_bytes(CLIENT_ID_LEN)
        self.client_nonce = secrets.token_bytes(NONCE_LEN)
        #: the name the server shows for this device
        self.device = default_device() if device is None else str(device)
        self.crypto = None
        self.server_id = None
        self.server_nonce = None
        self.flows = {}
        self._next_flow_id = 1
        self.closed = False
        self.running = True
        self._send_lock = threading.Lock()
        self._flows_lock = threading.RLock()
        self._pump_thread = None
        #: when the server answered the last ping
        self.last_answer = time.time()
        self._ping_id = 0
        #: the pieces of the report the server sent, by their offset
        self._report_pieces = {}
        self._report_total = None

    # -- heartbeat ----------------------------------------------------------
    def ping(self):
        """Ask the server whether it is still there."""
        header = proto.build_header(proto.PING, self._ping_id, 0)
        with self._send_lock:
            self.sock.sendto(self.crypto.encrypt(header, b""), self.server_addr)
        self._ping_id += 1

    def reconnect(self, timeout=15.0):
        """Do the handshake again, for example when the server went away."""
        try:
            self.handshake()
            return True
        except (TunnelError, OSError):
            return False

    # -- handshake ----------------------------------------------------------
    def handshake(self):
        """Do the handshake.

        It holds the lock of the frames, so no frame of the old session can
        slip out in the middle of it.
        """
        with self._send_lock:
            return self._handshake()

    def _handshake(self):
        # Throw away what is left of the old session.  Otherwise the buffer of
        # the socket is full and the answer of the server, which is the
        # newest datagram, is simply dropped.
        self._drain()

        # a new session gets new numbers, so a reconnect starts from scratch
        self.client_id = secrets.token_bytes(CLIENT_ID_LEN)
        self.client_nonce = secrets.token_bytes(NONCE_LEN)
        self._send_counter = 0
        self._recv_counter = 0
        self.last_answer = time.time()

        proof = hello_proof(self.master, self.client_id, self.client_nonce)
        payload = proto.build_hello(self.client_id, self.client_nonce, proof, self.device)
        header = proto.build_header(proto.HELLO, 0, len(payload))
        self.sock.sendto(seal_with_master(self.master, header, payload), self.server_addr)

        data, _ = self.sock.recvfrom(65535)
        header, payload = self._read_the_answer(data)
        parsed = proto.parse_header(header)
        if parsed["type"] != proto.HELLO_ACK:
            raise TunnelError("expected HELLO_ACK, got %s" % proto.type_name(parsed["type"]))
        if len(payload) < CLIENT_ID_LEN + NONCE_LEN + PROOF_LEN:
            raise TunnelError("short HELLO_ACK")
        self.server_id = payload[:CLIENT_ID_LEN]
        self.server_nonce = payload[CLIENT_ID_LEN:CLIENT_ID_LEN + NONCE_LEN]
        proof = payload[CLIENT_ID_LEN + NONCE_LEN:]
        expected = ack_proof(
            self.master, self.client_id, self.server_id, self.client_nonce, self.server_nonce
        )
        if proof != expected:
            raise TunnelError("the server did not prove it knows the master key")

        key = derive_session_key(
            self.master, self.client_id, self.server_id, self.client_nonce, self.server_nonce
        )
        self.crypto = SessionCrypto(key, send_id=self.client_id, recv_id=self.server_id)
        self.last_answer = time.time()
        return self

    def _drain(self):
        """Read and throw away everything that is still in the buffer."""
        self.sock.settimeout(0.05)
        try:
            while True:
                self.sock.recvfrom(65535)
        except (socket.timeout, OSError):
            pass
        finally:
            self.sock.settimeout(self.timeout)

    def _read_the_answer(self, data):
        """The answer of the server.

        After a reconnect there can still be frames of the old session in the
        buffer.  They are not for us and must not stop the handshake, so they
        are skipped.
        """
        deadline = time.time() + 15.0
        while True:
            try:
                header, payload = unseal_with_master(self.master, data)
            except CryptoError:
                header, payload = None, None
            if header is not None and proto.parse_header(header)["type"] == proto.HELLO_ACK:
                return header, payload
            if time.time() > deadline:
                raise TunnelError("the server did not answer the handshake")
            try:
                data, _ = self.sock.recvfrom(65535)
            except socket.timeout:
                raise TunnelError("the server did not answer the handshake")

    # -- flows --------------------------------------------------------------
    def open_flow(self, dst_host, dst_port, protocol=proto.IPPROTO_TCP,
                  src_ip=None, src_port=0, resolve=False):
        """Ask the server to open a flow.  Returns the flow object."""
        with self._flows_lock:
            flow_id = self._next_flow_id
            self._next_flow_id += 1
        dst_ip = None
        if not resolve:
            try:
                dst_ip = socket.gethostbyname(dst_host)
            except socket.gaierror:
                dst_ip = None
        payload = proto.build_open(
            protocol,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            dst_name=dst_host if (resolve or dst_ip is None) else None,
        )
        header = proto.build_header(proto.OPEN, flow_id, len(payload))
        with self._send_lock:
            self.sock.sendto(self.crypto.encrypt(header, payload), self.server_addr)
        flow = RemoteFlow(flow_id, dst_host, dst_port, protocol)
        with self._flows_lock:
            self.flows[flow_id] = flow
        return flow

    def send(self, flow_id, data, datagram=False):
        """Send bytes to the server for a flow."""
        with self._send_lock:
            if datagram:
                total = len(data)
                offset = 0
                while offset < total:
                    # two bytes of the payload are the length of the
                    # datagram, the rest has to fit into one frame
                    chunk = data[offset:offset + proto.MAX_DATA - 2]
                    payload = struct.pack("!H", total) + chunk
                    header = proto.build_header(
                        proto.DATA, flow_id, len(payload), proto.FLAG_DATAGRAM
                    )
                    self.sock.sendto(self.crypto.encrypt(header, payload), self.server_addr)
                    offset += len(chunk)
            else:
                offset = 0
                while offset < len(data):
                    chunk = data[offset:offset + proto.MAX_DATA]
                    header = proto.build_header(proto.DATA, flow_id, len(chunk))
                    self.sock.sendto(self.crypto.encrypt(header, chunk), self.server_addr)
                    offset += len(chunk)
        flow = self.flows.get(flow_id)
        if flow is not None:
            flow.bytes_out += len(data)

    def close_flow(self, flow_id, reason=proto.CLOSE_NORMAL):
        header = proto.build_header(proto.CLOSE, flow_id, 1)
        with self._send_lock:
            self.sock.sendto(self.crypto.encrypt(header, bytes([reason])), self.server_addr)

    # -- the report ---------------------------------------------------------
    def request_report(self):
        """Ask the server for the report of the traffic it has seen."""
        header = proto.build_header(proto.REPORT_REQ, 0, 0)
        with self._send_lock:
            self.sock.sendto(self.crypto.encrypt(header, b""), self.server_addr)

    def wait_for_report(self, timeout=30.0):
        """Wait for the report and return it as text.

        The report is bigger than one frame, so it comes in pieces.  They
        are put back together here.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.pump(timeout=0.5)
            with self._flows_lock:
                pieces = dict(self._report_pieces)
                total = self._report_total
            if total is None:
                continue
            if sum(len(piece) for piece in pieces.values()) < total:
                continue
            out = bytearray()
            offset = 0
            while offset < total:
                piece = pieces.get(offset)
                if piece is None:
                    break
                out += piece
                offset += len(piece)
            if offset >= total:
                return bytes(out).decode("utf-8", "replace")
        raise TunnelError("the server did not send the report in time")

    # -- receiving ----------------------------------------------------------
    def start_pump(self, on_data=None):
        """Read frames in the background until the client is closed."""
        if self._pump_thread is not None:
            return
        self._pump_thread = threading.Thread(
            target=self._pump_loop, args=(on_data,), daemon=True, name="tunnel-pump"
        )
        self._pump_thread.start()

    def _pump_loop(self, on_data):
        while self.running:
            try:
                self.pump(timeout=0.5, on_data=on_data)
            except (TunnelError, OSError):
                break

    def pump(self, timeout=None, on_data=None):
        """Read whatever is available and dispatch it.

        Returns the number of frames processed.
        """
        if timeout is not None:
            self.sock.settimeout(timeout)
        frames = 0
        try:
            while True:
                try:
                    data, _ = self.sock.recvfrom(65535)
                except socket.timeout:
                    break
                except BlockingIOError:
                    break
                self._dispatch(data, on_data)
                frames += 1
        finally:
            if timeout is not None:
                self.sock.settimeout(self.timeout)
        return frames

    def _dispatch(self, data, on_data=None):
        try:
            opened = self.crypto.decrypt(data)
        except CryptoError as exc:
            raise TunnelError("cannot decrypt the answer: %s" % exc)
        if opened is None:
            # a frame of an older session, not for us
            return
        header, payload = opened
        parsed = proto.parse_header(header)
        ftype = parsed["type"]
        flow_id = parsed["flow_id"]

        if ftype == proto.OPEN_OK:
            status = payload[0] if payload else proto.ERR_BAD_REQUEST
            with self._flows_lock:
                flow = self.flows.get(flow_id)
            if flow is not None:
                with flow._condition:
                    flow.status = status
                    flow._condition.notify_all()
        elif ftype == proto.DATA:
            with self._flows_lock:
                flow = self.flows.get(flow_id)
            if flow is None:
                return
            if parsed["flags"] & proto.FLAG_DATAGRAM:
                total = struct.unpack("!H", payload[:2])[0]
                flow.dgram_buf += payload[2:]
                while len(flow.dgram_buf) >= total:
                    datagram = flow.dgram_buf[:total]
                    flow.dgram_buf = flow.dgram_buf[total:]
                    flow.bytes_in += len(datagram)
                    flow.append(datagram, is_datagram=True)
                    if on_data is not None:
                        on_data(flow, datagram, True)
            else:
                flow.bytes_in += len(payload)
                flow.append(payload)
                if on_data is not None:
                    on_data(flow, payload, False)
        elif ftype == proto.CLOSE:
            with self._flows_lock:
                flow = self.flows.get(flow_id)
            if flow is not None:
                flow.closed = True
                flow.mark_eof()
        elif ftype == proto.PONG:
            # the server is still there
            self.last_answer = time.time()
        elif ftype == proto.REPORT_RES:
            chunk = proto.parse_report_chunk(payload)
            with self._flows_lock:
                self._report_pieces[chunk["offset"]] = chunk["text"]
                self._report_total = chunk["total"]

    def close(self):
        self.running = False
        if not self.closed:
            try:
                self.sock.close()
            except OSError:
                pass
            self.closed = True
