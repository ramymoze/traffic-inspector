"""Turn the inspector CSV into an answer instead of a table.

    python tools/analyze.py --csv traffic.csv

The report is built around the two things that were interesting in the
original story: a connection to an unknown destination on an odd port, and a
sustained upload that happens in the middle of the night.

With ``--baseline`` the destinations and ports of an older file are the
reference, so only what is *new* is reported:

    python tools/analyze.py --csv traffic.csv --baseline traffic-last-week.csv
"""

import argparse
import csv
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.inspector import FIELDS  # noqa: E402

#: Ports of the services that are normal.  Everything else is worth a look.
KNOWN_PORTS = {
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123, 135, 137, 138, 139, 143,
    161, 162, 179, 194, 389, 443, 445, 465, 514, 546, 547, 587, 631, 636, 993, 995,
    1080, 1433, 1434, 1521, 1723, 2049, 3128, 3306, 3389, 5000, 5432, 5900, 6379,
    8080, 8443, 8888, 9000, 9090, 27017, 28017,
}

#: A port above this is unusual for a phone.
HIGH_PORT = 1024


class Finding:
    """Something worth a look."""

    def __init__(self, kind, severity, title, detail=""):
        self.kind = kind
        self.severity = severity  # "high", "medium", "low"
        self.title = title
        self.detail = detail


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="analyse a traffic-inspector CSV file")
    parser.add_argument("--csv", default="traffic.csv", help="CSV file to read")
    parser.add_argument(
        "--baseline",
        default=None,
        help="an older CSV, only what is new compared to it is reported",
    )
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
    parser.add_argument(
        "--quiet-mb", type=float, default=0.0, help="bytes in the quiet hours that are reported"
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


def human_duration(seconds):
    """A duration in words, not in bytes."""
    seconds = float(seconds)
    if seconds < 90:
        return "%.0f seconds" % seconds
    if seconds < 5400:
        return "%.1f minutes" % (seconds / 60.0)
    if seconds < 172800:
        return "%.1f hours" % (seconds / 3600.0)
    return "%.1f days" % (seconds / 86400.0)


def destination_of(row):
    return row.get("dst_name") or row.get("dst_ip") or "?"


def device_of(row):
    return row.get("device") or "(unnamed)"


def port_of(row):
    return as_int(row.get("dst_port"), 0)


# -- the findings -----------------------------------------------------------
def find_streams(rows, upload_bytes, upload_seconds):
    """A long upload is what a camera or a backup looks like."""
    findings = []
    for row in rows:
        up = as_int(row["bytes_up"])
        duration = as_float(row["duration_s"])
        if up < upload_bytes or duration < upload_seconds:
            continue
        rate = up / duration if duration else 0
        findings.append(
            Finding(
                "stream",
                "high",
                "%.1f MB uploaded to %s:%s at %s, over %s"
                % (up / 1048576.0, row.get("dst_ip"), row.get("dst_port"),
                   row.get("time_of_day"), human_duration(duration)),
                "%.0f KB per second, that looks like a stream" % (rate / 1024.0),
            )
        )
    return findings


def find_quiet_hours(rows, quiet_start, quiet_end, quiet_bytes):
    """What happened while everybody was asleep."""
    findings = []
    quiet = [r for r in rows if quiet_start <= hour_of(r) < quiet_end]
    if not quiet:
        return findings
    up = sum(as_int(r["bytes_up"]) for r in quiet)
    down = sum(as_int(r["bytes_down"]) for r in quiet)
    if up < quiet_bytes and down < quiet_bytes:
        return findings
    by_device = defaultdict(lambda: [0, 0, 0])
    for row in quiet:
        entry = by_device[device_of(row)]
        entry[0] += as_int(row["bytes_up"])
        entry[1] += as_int(row["bytes_down"])
        entry[2] += 1
    for device, (up_bytes, down_bytes, count) in sorted(
        by_device.items(), key=lambda kv: -(kv[1][0] + kv[1][1])
    ):
        findings.append(
            Finding(
                "quiet",
                "medium",
                "%s moved %s up and %s down between %02d:00 and %02d:00"
                % (device, human(up_bytes), human(down_bytes), quiet_start, quiet_end),
                "%d flow(s)" % count,
            )
        )
    return findings


def find_new_destinations(rows, baseline):
    """Destinations and ports that were not there before."""
    findings = []
    if not baseline:
        return findings
    known = set()
    known_ports = set()
    for row in baseline:
        known.add(destination_of(row))
        known_ports.add(port_of(row))
    seen = set()
    for row in rows:
        dest = destination_of(row)
        port = port_of(row)
        if dest in seen:
            continue
        seen.add(dest)
        if dest in known:
            continue
        if port and port in known_ports:
            continue
        unusual = port and (port not in KNOWN_PORTS or port >= HIGH_PORT)
        findings.append(
            Finding(
                "new",
                "high" if unusual else "low",
                "new destination %s:%s at %s" % (row.get("dst_ip"), row.get("dst_port"),
                                                   row.get("time_of_day")),
                "the port is not one of the usual ones" if unusual else "",
            )
        )
    return findings


def find_odd_ports(rows):
    """Ports that are not the usual ones, seen in this file."""
    findings = []
    ports = Counter()
    where = {}
    for row in rows:
        port = port_of(row)
        if not port or port in KNOWN_PORTS:
            continue
        ports[port] += 1
        where.setdefault(port, (row.get("dst_ip"), row.get("time_of_day"), row.get("service")))
    for port, count in ports.most_common(10):
        ip, at, service = where[port]
        findings.append(
            Finding(
                "port",
                "medium",
                "port %d is not a known service (%s), %d flow(s)" % (port, service, count),
                "first seen at %s towards %s" % (at, ip),
            )
        )
    return findings


def find_long_absence(rows):
    """A device that was quiet and then suddenly is not."""
    findings = []
    by_device = defaultdict(list)
    for row in rows:
        by_device[device_of(row)].append(row)
    for device, device_rows in by_device.items():
        if len(device_rows) < 2:
            continue
        device_rows.sort(key=lambda r: r.get("ts_start") or "")
        total = sum(as_int(r["bytes_up"]) + as_int(r["bytes_down"]) for r in device_rows)
        if total < 1024 * 1024:
            continue
        first = device_rows[0].get("time_of_day")
        last = device_rows[-1].get("time_of_day")
        if first == last:
            continue
        findings.append(
            Finding(
                "device",
                "low",
                "%s moved %s between %s and %s" % (device, human(total), first, last),
                "%d flow(s)" % len(device_rows),
            )
        )
    return findings


def collect_findings(rows, baseline, args):
    findings = []
    findings += find_streams(rows, args.upload_mb * 1048576.0, args.upload_seconds)
    findings += find_quiet_hours(rows, args.quiet_start, args.quiet_end, args.quiet_mb)
    findings += find_new_destinations(rows, baseline)
    findings += find_odd_ports(rows)
    findings += find_long_absence(rows)
    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: order.get(f.severity, 3))
    return findings


# -- the report -------------------------------------------------------------
def report(rows, findings, args):
    if not rows:
        print("the file is empty")
        return

    total_up = sum(as_int(r["bytes_up"]) for r in rows)
    total_down = sum(as_int(r["bytes_down"]) for r in rows)
    active = [r for r in rows if r.get("state") == "active"]
    times = sorted(r.get("time_of_day") for r in rows if r.get("time_of_day"))

    print("=" * 72)
    print("traffic-inspector report  -  %d flow(s)" % len(rows))
    print("=" * 72)
    print("uploaded    %s" % human(total_up))
    print("downloaded  %s" % human(total_down))
    print("still open  %d" % len(active))
    if times:
        print("between     %s and %s" % (times[0], times[-1]))
    print()

    if findings:
        print("-- worth a look " + "-" * 55)
        for number, finding in enumerate(findings, 1):
            print("  %d. [%s] %s" % (number, finding.severity.upper(), finding.title))
            if finding.detail:
                print("       %s" % finding.detail)
        print()
    else:
        print("-- worth a look " + "-" * 55)
        print("  nothing unusual")
        print()

    # -- devices ----------------------------------------------------------
    print("-- devices -------------------------------------------------------")
    by_device = defaultdict(lambda: [0, 0, 0, "", ""])
    for row in rows:
        entry = by_device[device_of(row)]
        entry[0] += as_int(row["bytes_down"]) + as_int(row["bytes_up"])
        entry[1] += 1
        entry[2] += as_int(row["bytes_up"])
        start = row.get("ts_start") or ""
        end = row.get("ts_end") or ""
        if start and (not entry[3] or start < entry[3]):
            entry[3] = start
        if end > entry[4]:
            entry[4] = end
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
    print("-- destinations -------------------------------------------------")
    by_dest = defaultdict(lambda: [0, 0, 0])
    for row in rows:
        entry = by_dest[destination_of(row)]
        entry[0] += as_int(row["bytes_down"])
        entry[1] += as_int(row["bytes_up"])
        entry[2] += 1
    for dest, (down, up, count) in sorted(
        by_dest.items(), key=lambda kv: -(kv[1][0] + kv[1][1])
    )[:15]:
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
    baseline = None
    if args.baseline and os.path.exists(args.baseline):
        baseline = load(args.baseline)
    findings = collect_findings(rows, baseline, args)
    report(rows, findings, args)
    # something to look at?  the exit code says so, handy for a cron job
    return 1 if any(f.severity == "high" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
