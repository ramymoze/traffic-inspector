"""The traffic-inspector client.

It puts the whole traffic of the machine into the tunnel:

    python -m client.main --server 192.168.1.10 --port 5555

The pieces are:

* the TUN device, which catches the IP packets of the kernel
* the bridge, which turns them into tunnel flows
* the tunnel client, which carries them to the server

On Linux the interface and the routes are set up automatically, which needs
root.  On Windows the adapter comes from Wintun, the routes are set up with
``netsh`` and the whole thing needs an elevated prompt.  Use ``--no-setup``
when the routes are managed by something else.
"""

import argparse
import os
import signal
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client.bridge import TcpBridge  # noqa: E402
from client.tunnel import TunnelClient, TunnelError  # noqa: E402
from server.crypto import load_master_key  # noqa: E402


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="traffic-inspector VPN client")
    parser.add_argument("--server", required=True, help="address of the tunnel server")
    parser.add_argument("--port", type=int, default=5555, help="UDP port of the server")
    parser.add_argument("--tun", default="ti0", help="name of the tunnel interface")
    parser.add_argument(
        "--address", default="10.8.0.1/24", help="address of the tunnel interface"
    )
    parser.add_argument(
        "--dns", default="8.8.8.8,1.1.1.1", help="resolvers to use through the tunnel"
    )
    parser.add_argument("--mss", type=int, default=1160, help="maximum segment size")
    parser.add_argument("--key-file", default=None, help="file holding the master key")
    parser.add_argument(
        "--device",
        default=None,
        help="the name the server shows for this device (default: the system and the hostname)",
    )
    parser.add_argument(
        "--no-setup", action="store_true", help="do not touch the routes or the resolver"
    )
    parser.add_argument(
        "--wintun",
        default=None,
        help="the Wintun driver to use on Windows (default: client/wintun.dll)",
    )
    parser.add_argument(
        "--keep-routes", action="store_true", help="leave the routes alone on exit"
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if os.name == "nt":
        from client.tun_windows import WintunTun, setup, teardown
    else:
        from client.tun_linux import LinuxTun, setup, teardown

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
    print("[+] Connected to the tunnel server at %s:%d" % (args.server, args.port))

    bridge = TcpBridge(
        client,
        local_ip=args.address.split("/")[0],
        mss=args.mss,
        dns_server=args.dns.split(",")[0].strip(),
        verbose=True,
    )
    client.start_pump(bridge.on_tunnel_data)

    if os.name == "nt":
        # the adapter has to exist before it can get an address
        try:
            tun = WintunTun(args.tun, dll=args.wintun).open()
        except Exception as exc:
            print("Cannot open the Wintun adapter: %s" % exc, file=sys.stderr)
            client.close()
            return 1
        if not args.no_setup:
            setup(args.tun, args.address, server=args.server, dns=args.dns)
    else:
        if not args.no_setup:
            setup(args.tun, args.address, server=args.server, dns=args.dns)
        tun = LinuxTun(args.tun).open()
    print("[*] The traffic of this machine now goes through the tunnel.")

    running = {"value": True}

    def stop(*_args):
        running["value"] = False

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    try:
        while running["value"]:
            packet = tun.read(timeout=0.1)
            if packet:
                bridge.handle_packet(packet)
            bridge.pump()
            for packet in bridge.take_output():
                tun.write(packet)
    finally:
        tun.close()
        if not args.no_setup and not args.keep_routes:
            teardown(args.tun, args.address, server=args.server)
        client.close()
        print("\n[*] The tunnel is down.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
