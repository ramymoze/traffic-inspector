"""Stub client for the traffic-inspector tunnel.

It does not need a TUN device: it opens a flow to one destination, sends a
request and prints what comes back.  It is the quickest way to see the server
work and to fill the CSV with real rows.

    python testing.py                       # GET / on www.google.com:80
    python testing.py example.com 443       # TCP connect to example.com:443
    python testing.py 1.1.1.1 53 --udp      # a DNS style UDP query
"""

import argparse
import socket
import sys
import time

from client.tunnel import TunnelClient, TunnelError
from server import protocol as proto
from server.crypto import load_master_key


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="traffic-inspector stub client")
    parser.add_argument("host", nargs="?", default="www.google.com", help="destination host")
    parser.add_argument("port", nargs="?", type=int, default=80, help="destination port")
    parser.add_argument("--udp", action="store_true", help="use UDP instead of TCP")
    parser.add_argument(
        "--no-resolve",
        action="store_true",
        help="resolve the destination locally instead of letting the server do it",
    )
    parser.add_argument(
        "--request",
        default=None,
        help="raw request to send (default: an HTTP GET for TCP)",
    )
    parser.add_argument("--server", default="127.0.0.1", help="server address")
    parser.add_argument("--server-port", type=int, default=5555, help="server port")
    parser.add_argument("--wait", type=float, default=5.0, help="seconds to wait for the answer")
    parser.add_argument(
        "--src-ip",
        default=None,
        help="source address to report to the server (default: the local outbound address)",
    )
    parser.add_argument("--src-port", type=int, default=0, help="source port to report")
    parser.add_argument("--key-file", default=None, help="file holding the master key")
    return parser.parse_args(argv)


def local_source_address(host, port):
    """Best effort guess of the local address used to reach ``host``."""
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect((host, port))
            return probe.getsockname()[0]
        finally:
            probe.close()
    except OSError:
        return None


def main(argv=None):
    args = parse_args(argv)
    master = load_master_key(args.key_file)

    client = TunnelClient((args.server, args.server_port), master)
    try:
        client.handshake()
    except (TunnelError, OSError) as exc:
        print("Handshake failed: %s" % exc, file=sys.stderr)
        return 1

    protocol = proto.IPPROTO_UDP if args.udp else proto.IPPROTO_TCP
    src_ip = args.src_ip
    if src_ip is None:
        src_ip = local_source_address(args.host, args.port)
    flow = client.open_flow(
        args.host,
        args.port,
        protocol=protocol,
        src_ip=src_ip,
        src_port=args.src_port,
        resolve=not args.no_resolve,
    )

    request = args.request
    if request is None and not args.udp:
        request = "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: traffic-inspector\r\n\r\n" % args.host
    if request is not None:
        client.send(flow.flow_id, request.encode())

    received = []

    def on_data(flow, data, is_datagram):
        received.append(data)

    deadline = time.time() + args.wait
    while time.time() < deadline:
        client.pump(timeout=0.5, on_data=on_data)
        if flow.closed:
            break
        if received and not args.udp:
            # A TCP flow is a stream, give it a moment to settle.
            if time.time() > deadline - args.wait + 1.0:
                break

    client.pump(timeout=0.2, on_data=on_data)
    print("[*] flow %d: sent %d bytes, received %d bytes" % (
        flow.flow_id, flow.bytes_out, flow.bytes_in))
    if flow.status is not None and flow.status != proto.OK:
        print("[!] the server refused the flow: %s" % proto.status_name(flow.status))
    if received:
        sys.stdout.buffer.write(b"".join(received))
        sys.stdout.buffer.flush()
        print()
    client.close_flow(flow.flow_id)
    client.pump(timeout=0.3)
    client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
