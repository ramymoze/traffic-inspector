"""Turn the inspector CSV into something you can actually read.

    python tools/analyze.py --csv traffic.csv

The report is built around the two things that were interesting in the
original story: a connection to an unknown destination on an odd port, and a
sustained upload that happens in the middle of the night.
"""

import argparse
import csv
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.inspector import FIELDS  # noqa: E402

KNOWN_PORTS = {
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123, 135, 137, 138, 139, 143,
    161, 162, 179, 194, 389, 443, 445, 465, 514, 546, 547, 587, 631, 636, 993, 995,
    1080, 1433, 1434, 1521, 1723, 2049, 3128, 3306, 3389, 5000, 5432, 5900, 6379,
    8080, 8443, 8888, 9000, 9090, 27017, 28017, 3389,
}


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="analyse a traffic-inspector CSV file")
    parser.add_argument("--csv", default="traffic.csv", help="CSV file to read")
    parser.add_argument(
        "--quiet-start", type=int, default=0, help="first hour of the quiet period (default 0)"
    )
    parser.add_argument(
        "--quiet-end", type=int, default=5, help="hour after the quiet period (default 5)"
    )
    parser.add_argument(
        "--upload-mb", type=float, default=5.0, help="upload size that counts as a stream"
    )
    parser.add_argument(
        "--upload-seconds", type=float, default=60.0, help="minimum duration of a stream"
    )
    return parser.parse_args(argv)


def load(path):
    rows = []
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = set(FIELDS) - set(reader.fieldnames or [])
        if missing:
            raise SystemExit("the file is missing the columns: %s" % ", ".join(sorted(missing)))
        for row in reader:
            rows.append(row)
    return rows


def as_int(value, default=0):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def as_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def hour_of(row):
    stamp = row.get("time_of_day") or ""
    try:
        return int(stamp.split(":")[0])
    except (IndexError, ValueError):
        return -1


def human(size):
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return "%.1f %s" % (value, unit)
        value /= 1024
    return "%.1f TB" % value


def destination_of(row):
    name = row.get("dst_name") or ""
    return name or row.get("dst_ip") or "?"


def report(rows, args):
    if not rows:
        print("the file is empty")
        return

    total_up = sum(as_int(r["bytes_up"]) for r in rows)
    total_down = sum(as_int(r["bytes_down"]) for r in rows)
    active = [r for r in rows if r.get("state") == "active"]

    print("=" * 72)
    print("traffic-inspector report  -  %d flows" % len(rows))
    print("=" * 72)
    print("uploaded    %s" % human(total_up))
    print("downloaded  %s" % human(total_down))
    print("still open  %d" % len(active))
    print()

    # -- destinations -----------------------------------------------------
    print("-- devices -------------------------------------------------------")
    by_device = defaultdict(lambda: [0, 0, 0, "", ""])
    for row in rows:
        device = row.get("device") or "(unnamed)"
        entry = by_device[device]
        entry[0] += as_int(row["bytes_down"]) + as_int(row["bytes_up"])
        entry[1] += 1
        entry[2] += as_int(row["bytes_up"])
        start = row.get("ts_start") or ""
        end = row.get("ts_end") or ""
        if start and (not entry[3] or start < entry[3]):
            entry[3] = start
        if end > entry[4]:
            entry[4] = end
    if by_device:
        for device, (size, count, up, start, end) in sorted(
            by_device.items(), key=lambda kv: -kv[1][0]
        ):
            print(
                "  %-30s %4d flow(s)  %-10s  up %-10s  %s -> %s"
                % (device[:30], count, human(size), human(up),
                   (start or "?")[:19], (end or "still open")[:19])
            )
    print()

    # -- destinations -----------------------------------------------------
    print("-- destinations ------------------------------------------------")
    by_dest = defaultdict(lambda: [0, 0, 0])
    for row in rows:
        entry = by_dest[destination_of(row)]
        entry[0] += as_int(row["bytes_down"])
        entry[1] += as_int(row["bytes_up"])
        entry[2] += 1
    for dest, (down, up, count) in sorted(by_dest.items(), key=lambda kv: -(kv[1][0] + kv[1][1]))[:15]:
        print(
            "  %-40s %4d flow(s)  up %-10s down %s"
            % (dest[:40], count, human(up), human(down))
        )
    print()

    # -- ports and services ----------------------------------------------
    print("-- ports and services -------------------------------------------")
    by_port = defaultdict(lambda: [0, 0, ""])
    for row in rows:
        entry = by_port[row.get("dst_port") or "?"]
        entry[0] += as_int(row["bytes_down"]) + as_int(row["bytes_up"])
        entry[1] += 1
        entry[2] = row.get("service") or ""
    for port, (size, count, service) in sorted(by_port.items(), key=lambda kv: -kv[1][0])[:15]:
        print("  port %-8s %-16s %4d flow(s)  %s" % (port, service, count, human(size)))
    print()

    # -- unusual ports ---------------------------------------------------
    unusual = sorted(
        {
            (row.get("dst_port"), row.get("service") or "", destination_of(row))
            for row in rows
            if row.get("dst_port") and as_int(row["dst_port"]) not in KNOWN_PORTS
        }
    )
    if unusual:
        print("-- uncommon ports (worth a look) ------------------------------")
        for port, service, dest in unusual[:20]:
            print("  %-8s %-16s %s" % (port, service, dest))
        print()

    # -- activity by hour -------------------------------------------------
    print("-- activity by hour of day ---------------------------------------")
    hours = Counter()
    for row in rows:
        hour = hour_of(row)
        if hour >= 0:
            hours[hour] += 1
    if hours:
        peak = max(hours.values())
        for hour in range(24):
            count = hours.get(hour, 0)
            bar = "#" * int(30 * count / peak) if peak else ""
            print("  %02d:00  %4d %s" % (hour, count, bar))
    print()

    # -- quiet hours ------------------------------------------------------
    quiet = [
        row
        for row in rows
        if args.quiet_start <= hour_of(row) < args.quiet_end
    ]
    if quiet:
        print("-- activity during the quiet hours (%02d:00 - %02d:00) ---------" % (
            args.quiet_start, args.quiet_end))
        for row in sorted(quiet, key=lambda r: r.get("time_of_day") or "")[:20]:
            print(
                "  %s  %-16s %s -> %s:%s  %s  up %s / down %s  (%s s)"
                % (
                    row.get("time_of_day"),
                    (row.get("device") or "?")[:16],
                    row.get("src_ip") or row.get("tunnel_src"),
                    row.get("dst_ip"),
                    row.get("dst_port"),
                    row.get("service"),
                    human(as_int(row["bytes_up"])),
                    human(as_int(row["bytes_down"])),
                    row.get("duration_s"),
                )
            )
        print()

    # -- long uploads (the webcam heuristic) ------------------------------
    threshold = args.upload_mb * 1024 * 1024
    streams = [
        row
        for row in rows
        if as_int(row["bytes_up"]) >= threshold
        and as_float(row["duration_s"]) >= args.upload_seconds
    ]
    if streams:
        print("-- long uploads (possible camera or bulk transfer) -------------")
        for row in sorted(streams, key=lambda r: -as_int(r["bytes_up"]))[:20]:
            print(
                "  %s  -> %s:%s  up %s over %s s"
                % (
                    row.get("time_of_day"),
                    row.get("dst_ip"),
                    row.get("dst_port"),
                    human(as_int(row["bytes_up"])),
                    row.get("duration_s"),
                )
            )
        print()

    # -- first seen destinations -------------------------------------------
    print("-- first seen destinations ---------------------------------------")
    first = {}
    for row in sorted(rows, key=lambda r: r.get("ts_start") or ""):
        dest = destination_of(row)
        if dest not in first:
            first[dest] = row
    for dest, row in list(first.items())[:20]:
        print("  %-40s first seen %s" % (dest[:40], row.get("ts_start")))
    print()


def main(argv=None):
    args = parse_args(argv)
    rows = load(args.csv)
    report(rows, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
