"""End to end test of the traffic-inspector server with a real device.

Start this script on the machine that runs the server.  It prints the details
your device needs, waits for the device to connect, shows the live log, and
finally prints the CSV and the analysis report.

    python tools/device_test.py

The device can be a phone, a tablet or a laptop.  The simplest way to get
traffic through the tunnel today is the SOCKS5 client:

    python -m client.socks --server <address of this machine> --port 5555

and then point a browser at ``socks5://127.0.0.1:1080`` on the device.
"""

import argparse
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.crypto import load_master_key  # noqa: E402
from server.inspector import FIELDS  # noqa: E402
from server.server import TunnelServer  # noqa: E402
from tools import analyze  # noqa: E402

KEY_FILE = None


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="test the traffic-inspector server with a real device"
    )
    parser.add_argument("--host", default="0.0.0.0", help="address to bind (default 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5555, help="UDP port (default 5555)")
    parser.add_argument("--csv", default="traffic.csv", help="CSV file to write")
    parser.add_argument("--key-file", default=None, help="file holding the master key")
    parser.add_argument(
        "--expect-flows", type=int, default=1, help="how many flows to wait for (default 1)"
    )
    parser.add_argument(
        "--timeout", type=float, default=600.0, help="give up after this many seconds"
    )
    parser.add_argument(
        "--grace", type=float, default=5.0, help="wait this long after the last flow"
    )
    parser.add_argument(
        "--no-pause", action="store_true", help="do not wait for Enter before the report"
    )
    parser.add_argument("--hide-key", action="store_true", help="do not print the master key")
    return parser.parse_args(argv)


def local_addresses():
    """Every IPv4 address of this machine, the most likely one first."""
    addresses = set()
    primary = None
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("8.8.8.8", 80))
            primary = probe.getsockname()[0]
            addresses.add(primary)
        finally:
            probe.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addresses.add(info[4][0])
    except OSError:
        pass
    addresses.discard("127.0.0.1")
    addresses.discard("0.0.0.0")
    ordered = sorted(addresses)
    if primary in ordered:
        ordered.remove(primary)
        ordered.insert(0, primary)
    return primary, ordered


def banner(args, master):
    primary, addresses = local_addresses()
    print()
    print("=" * 72)
    print("  CONNECT YOUR DEVICE")
    print("=" * 72)
    if primary:
        print("  server address : %s:%d   (this is the one to use)" % (primary, args.port))
        others = [a for a in addresses if a != primary]
        if others:
            print("  other addresses: %s" % ", ".join("%s:%d" % (a, args.port) for a in others))
    elif addresses:
        for address in addresses:
            print("  server address : %s:%d" % (address, args.port))
    else:
        print("  server address : <this machine>:%d" % args.port)
    if not args.hide_key:
        print("  master key     : %s" % master.hex())
    print()
    print("  On the device:")
    print("    1. install the project and run:  pip install pycryptodome")
    if not args.hide_key:
        print("    2. export TRAFFIC_INSPECTOR_KEY=%s" % master.hex())
        print("       (or copy the %s file of the server to the device)" % (
            os.path.basename(args.key_file or ".env")))
    print("    3. python -m client.socks --server <address above> --port %d" % args.port)
    print("    4. in the browser of the device:  socks5://127.0.0.1:1080")
    print("    5. browse, then come back here")
    print()
    print("=" * 72)
    print("  waiting for the device ...")
    print("=" * 72)
    print()


def wait_for_flows(server, expected, timeout):
    """Wait until ``expected`` flows were recorded.  Returns True on success."""
    deadline = time.time() + timeout
    last = -1
    while time.time() < deadline:
        rows = server.inspector.rows()
        if len(rows) != last:
            last = len(rows)
        if len(rows) >= expected:
            return True
        time.sleep(0.2)
    return False


def verify(rows, expected):
    """Check the recorded rows look right."""
    checks = []

    def add(name, ok, detail=""):
        checks.append((name, ok, detail))

    add("at least %d flow(s) recorded" % expected, len(rows) >= expected,
        "%d recorded" % len(rows))
    if not rows:
        return checks

    missing = [f for f in FIELDS if f not in rows[0]]
    add("every column is present", not missing, ", ".join(missing) if missing else "")

    without_destination = [r for r in rows if not r.get("dst_ip") and not r.get("dst_name")]
    add("every flow has a destination", not without_destination,
        "%d without" % len(without_destination))

    without_service = [r for r in rows if not r.get("service")]
    add("every flow has a service", not without_service,
        "%d without" % len(without_service))

    without_time = [r for r in rows if not r.get("time_of_day")]
    add("every flow has a time of day", not without_time,
        "%d without" % len(without_time))

    without_bytes = [r for r in rows if not (r.get("bytes_up") or r.get("bytes_down"))]
    add("every flow moved some bytes", not without_bytes,
        "%d empty" % len(without_bytes))

    unknown_sources = [r for r in rows if not r.get("src_ip") and not r.get("tunnel_src")]
    add("every flow has a source", not unknown_sources,
        "%d without" % len(unknown_sources))

    return checks


def main(argv=None):
    args = parse_args(argv)

    try:
        master = load_master_key(args.key_file)
    except Exception as exc:
        print("Cannot read the master key: %s" % exc, file=sys.stderr)
        return 1

    server = TunnelServer(
        host=args.host,
        port=args.port,
        csv_path=args.csv,
        key_file=args.key_file,
        level="verbose",
    )
    import threading

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    time.sleep(0.5)

    banner(args, master)

    try:
        arrived = wait_for_flows(server, args.expect_flows, args.timeout)
        if not arrived:
            print()
            print("[!] No device showed up in time.")
        else:
            print()
            print("[+] %d flow(s) recorded, collecting for %.0f s ..." % (
                len(server.inspector.rows()), args.grace))
            time.sleep(args.grace)
    except KeyboardInterrupt:
        print()
        print("[*] Interrupted.")
    finally:
        server.running = False
        thread.join(timeout=3)
        try:
            server.inspector.maybe_write(force=True)
        except Exception:
            pass

    rows = []
    if os.path.exists(args.csv):
        import csv

        with open(args.csv, newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))

    print()
    print("=" * 72)
    print("  traffic.csv")
    print("=" * 72)
    with open(args.csv, newline="", encoding="utf-8") as handle:
        sys.stdout.write(handle.read().rstrip("\r\n"))
    print("\n")

    analyze.main(["--csv", args.csv])

    print("=" * 72)
    print("  CHECKS")
    print("=" * 72)
    failed = 0
    for name, ok, detail in verify(rows, args.expect_flows):
        print("  [%s] %-40s %s" % ("PASS" if ok else "FAIL", name, detail))
        if not ok:
            failed += 1
    print()
    if failed:
        print("  %d check(s) failed." % failed)
    else:
        print("  Everything checks out.")
    print()
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
