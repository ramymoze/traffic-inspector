"""A SOCKS5 proxy that sends everything through the tunnel.

It is the easiest way to put a browser through the tunnel: run this on the
machine that holds the browser, point it at ``127.0.0.1:1080`` and every
request travels through the tunnel to the server, where the inspector
records it.

    python -m client.socks --server 192.168.1.10 --port 5555

Only the CONNECT command is supported, which is what browsers use for HTTP
and HTTPS.
"""

import argparse
import os
import socket
import struct
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client.tunnel import TunnelClient, TunnelError  # noqa: E402
from server import protocol as proto  # noqa: E402
from server.crypto import load_master_key  # noqa: E402

SOCKS_VERSION = 5
CMD_CONNECT = 1
CMD_UDP_ASSOCIATE = 3
ATYP_IPV4 = 1
ATYP_DOMAIN = 3
ATYP_IPV6 = 4

# SOCKS5 reply codes
REPLY_OK = 0
REPLY_FAILURE = 1
REPLY_NOT_ALLOWED = 2
REPLY_NETWORK_UNREACHABLE = 3
REPLY_HOST_UNREACHABLE = 4
REPLY_REFUSED = 5
REPLY_COMMAND_NOT_SUPPORTED = 7

#: The status of the OPEN_OK answer mapped to a SOCKS5 reply code.
_STATUS_TO_REPLY = {
    proto.OK: REPLY_OK,
    proto.ERR_RESOLVE: REPLY_HOST_UNREACHABLE,
    proto.ERR_REFUSED: REPLY_REFUSED,
    proto.ERR_TIMEOUT: REPLY_NETWORK_UNREACHABLE,
    proto.ERR_CONNECT: REPLY_NETWORK_UNREACHABLE,
    proto.ERR_UNSUPPORTED: REPLY_COMMAND_NOT_SUPPORTED,
    proto.ERR_BAD_REQUEST: REPLY_FAILURE,
}


def _recv_exactly(sock, count):
    """Read exactly ``count`` bytes, or return None."""
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            return None
        data += chunk
    return data


class SocksProxy:
    """Forwards SOCKS5 CONNECT requests through the tunnel."""

    def __init__(self, client, host="127.0.0.1", port=1080, src_ip=None, verbose=True):
        self.client = client
        self.src_ip = src_ip
        self.verbose = verbose
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((host, port))
        self.listener.listen(16)
        self.count = 0
        self._lock = threading.Lock()

    @property
    def address(self):
        return self.listener.getsockname()

    def _say(self, message):
        if self.verbose:
            print("[*] %s" % message, flush=True)

    def serve_forever(self):
        self._say("SOCKS5 proxy listening on %s:%d" % self.address)
        while True:
            try:
                conn, addr = self.listener.accept()
            except OSError:
                return
            with self._lock:
                self.count += 1
                number = self.count
            threading.Thread(
                target=self.handle, args=(conn, addr, number), daemon=True
            ).start()

    # -- one client --------------------------------------------------------
    def handle(self, conn, addr, number):
        try:
            if not self._greet(conn):
                return
            request = self._read_request(conn)
            if request is None:
                return
            command, atyp, host, port = request
            if command != CMD_CONNECT:
                self._reply(conn, REPLY_COMMAND_NOT_SUPPORTED)
                return

            self._say("request %d: %s:%s from %s" % (number, host, port, addr[0]))
            flow = self.client.open_flow(
                host,
                port,
                protocol=proto.IPPROTO_TCP,
                src_ip=self.src_ip or addr[0],
                src_port=addr[1],
                resolve=(atyp == ATYP_DOMAIN),
            )
            status = flow.wait_status(timeout=20.0)
            if status is None:
                self._reply(conn, REPLY_NETWORK_UNREACHABLE)
                self.client.close_flow(flow.flow_id)
                return
            if status != proto.OK:
                self._say("request %d refused: %s" % (number, proto.status_name(status)))
                self._reply(conn, _STATUS_TO_REPLY.get(status, REPLY_FAILURE))
                self.client.close_flow(flow.flow_id)
                return

            self._reply(conn, REPLY_OK)
            self._pipe(conn, flow, number)
        except (OSError, TunnelError) as exc:
            self._say("request %d failed: %s" % (number, exc))
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _greet(self, conn):
        header = _recv_exactly(conn, 2)
        if header is None:
            return False
        nmethods = header[1]
        if nmethods:
            _recv_exactly(conn, nmethods)
        conn.sendall(bytes([SOCKS_VERSION, 0]))  # "no authentication required"
        return True

    def _read_request(self, conn):
        header = _recv_exactly(conn, 4)
        if header is None:
            return None
        version, command, _reserved, atyp = header
        if version != SOCKS_VERSION:
            return None
        if atyp == ATYP_IPV4:
            raw = _recv_exactly(conn, 4)
            if raw is None:
                return None
            host = socket.inet_ntoa(raw)
        elif atyp == ATYP_IPV6:
            raw = _recv_exactly(conn, 16)
            if raw is None:
                return None
            host = socket.inet_ntop(socket.AF_INET6, raw)
        elif atyp == ATYP_DOMAIN:
            length = _recv_exactly(conn, 1)
            if length is None:
                return None
            raw = _recv_exactly(conn, length[0])
            if raw is None:
                return None
            host = raw.decode("utf-8", "replace")
        else:
            return None
        raw_port = _recv_exactly(conn, 2)
        if raw_port is None:
            return None
        port = struct.unpack("!H", raw_port)[0]
        return command, atyp, host, port

    def _reply(self, conn, code):
        conn.sendall(bytes([SOCKS_VERSION, code, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0]))

    def _pipe(self, conn, flow, number):
        """Copy the bytes both ways until one side is done."""

        def to_tunnel():
            try:
                while True:
                    data = conn.recv(65536)
                    if not data:
                        break
                    self.client.send(flow.flow_id, data)
            except OSError:
                pass
            finally:
                try:
                    self.client.close_flow(flow.flow_id)
                except OSError:
                    pass

        uplink = threading.Thread(target=to_tunnel, daemon=True)
        uplink.start()

        try:
            while True:
                data = flow.read(timeout=1.0)
                if data:
                    conn.sendall(data)
                    continue
                if flow.closed:
                    break
        except OSError:
            pass
        self._say("request %d finished (%d bytes up, %d bytes down)" % (
            number, flow.bytes_out, flow.bytes_in))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="SOCKS5 proxy that tunnels everything through the traffic-inspector server"
    )
    parser.add_argument("--server", default="127.0.0.1", help="address of the tunnel server")
    parser.add_argument("--port", type=int, default=5555, help="UDP port of the tunnel server")
    parser.add_argument("--listen", default="127.0.0.1", help="address to listen on")
    parser.add_argument("--listen-port", type=int, default=1080, help="port to listen on")
    parser.add_argument("--src-ip", default=None, help="source address to report to the server")
    parser.add_argument("--key-file", default=None, help="file holding the master key")
    parser.add_argument(
        "--device",
        default=None,
        help="the name the server shows for this device (default: the system and the hostname)",
    )
    args = parser.parse_args(argv)

    try:
        master = load_master_key(args.key_file)
    except Exception as exc:
        print("Cannot read the master key: %s" % exc, file=sys.stderr)
        return 1

    client = TunnelClient((args.server, args.port), master, device=args.device)
    try:
        client.handshake()
    except (TunnelError, OSError) as exc:
        print("Cannot reach the server: %s" % exc, file=sys.stderr)
        return 1

    client.start_pump()
    print("[+] Connected to the tunnel server at %s:%d" % (args.server, args.port), flush=True)
    print("[*] Point the browser at socks5://%s:%d" % (args.listen, args.listen_port), flush=True)

    proxy = SocksProxy(client, args.listen, args.listen_port, src_ip=args.src_ip)
    try:
        proxy.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping.", flush=True)
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
