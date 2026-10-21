"""Turn the inspector CSV into a verdict.

This is the brain of the project: it looks at the rows of the CSV and says
what is worth a look.  The report answers the two questions the whole
project is about:

  * is a device talking to somewhere it should not?  (a new destination, a
    port that is not a normal service)
  * is a device sending something it should not?  (a stream that never
    stops, in the middle of the night)

Everything else - the destinations, the ports, the hour of the day - is in
the report below the verdict, for when you want to look at the details.

The module is used by three things:

* ``tools/analyze.py`` - the command line version, it prints the report
* the server, when a client asks for it over the tunnel
* the tests

With a baseline (the file of an earlier day) only what is *new* is
reported.
"""

import csv
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from .inspector import FIELDS

#: Ports of the services that are normal for a phone.
KNOWN_PORTS = {
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123, 135, 137, 138, 139, 143,
    161, 162, 179, 194, 389, 443, 465, 514, 546, 547, 587, 631, 636, 993, 995,
    1080, 1433, 1434, 1521, 1723, 2049, 3128, 3306, 3389, 5000, 5432, 5900, 6379,
    8080, 8443, 8888, 9000, 9090, 27017, 28017,
    # what a phone really uses
    1194, 19305, 19306, 19307, 19308, 19309,  # push of the play services
    3478, 3479, 3480, 3481,                   # stun and turn, for calls
    5222, 5223, 5228,                         # xmpp and the push of google
    5353, 5355,                               # the names in the local network
    32429,                                    # the local network of the play services
}

#: Ports a phone has no reason to use.
HIGH_PORT = 40000

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


class ReportError(Exception):
    """The report could not be made."""


class Finding:
    """Something worth a look."""

    def __init__(self, kind, severity, title, detail=""):
        self.kind = kind
        self.severity = severity
        self.title = title
        self.detail = detail


# -- helpers ----------------------------------------------------------------
def human(size):
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return "%.1f %s" % (value, unit)
        value /= 1024
    return "%.1f TB" % value


def human_duration(seconds):
    """A length of time in words."""
    seconds = float(seconds)
    if seconds < 90:
        return "%.0f seconds" % seconds
    if seconds < 5400:
        return "%.1f minutes" % (seconds / 60.0)
    if seconds < 172800:
        return "%.1f hours" % (seconds / 3600.0)
    return "%.1f days" % (seconds / 86400.0)


def rate(size, seconds):
    if seconds <= 0:
        return 0.0
    return size / seconds


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


def destination_of(row):
    return row.get("dst_name") or row.get("dst_ip") or "?"


def device_of(row):
    return row.get("device") or "(unnamed)"


def devices_of(rows):
    """The names of the devices in a file of rows."""
    return set(device_of(row) for row in rows)


def port_of(row):
    return as_int(row.get("dst_port"), 0)


# -- the detectors ----------------------------------------------------------
def find_streams(rows, min_rate, min_seconds):
    """Traffic that keeps going and never stops.

    A page loads in a second and then it is over.  A camera sends for
    minutes, at a steady rate, and nobody is watching.  The rate is what
    tells the two apart, not the amount.
    """
    findings = []
    for row in rows:
        up = as_int(row["bytes_up"])
        down = as_int(row["bytes_down"])
        duration = as_float(row["duration_s"])
        if duration < min_seconds:
            continue
        up_rate = rate(up, duration)
        down_rate = rate(down, duration)
        if up_rate >= min_rate:
            findings.append(
                Finding(
                    "stream",
                    "high",
                    "%s is sending to %s:%s since %s, %s at %s per second"
                    % (device_of(row), row.get("dst_ip"), row.get("dst_port"),
                       row.get("time_of_day"), human(up), human(up_rate)),
                    "it has been going for %s, that is what a camera looks like"
                    % human_duration(duration),
                )
            )
        elif down_rate >= min_rate * 4:
            findings.append(
                Finding(
                    "stream",
                    "low",
                    "%s is downloading from %s:%s at %s per second"
                    % (device_of(row), row.get("dst_ip"), row.get("dst_port"),
                       human(down_rate)),
                    "it has been going for %s" % human_duration(duration),
                )
            )
    return findings


def find_night_traffic(rows, quiet_start, quiet_end, baseline):
    """What happened while everybody was asleep."""
    findings = []
    quiet = [r for r in rows if quiet_start <= hour_of(r) < quiet_end]
    if not quiet:
        return findings

    by_device = defaultdict(lambda: [0, 0, 0])
    for row in quiet:
        entry = by_device[device_of(row)]
        entry[0] += as_int(row["bytes_up"])
        entry[1] += as_int(row["bytes_down"])
        entry[2] += 1

    # what the same device did in the same hours before
    before = defaultdict(lambda: [0, 0])
    known_devices = set()
    if baseline:
        known_devices = devices_of(baseline)
        for row in baseline:
            if quiet_start <= hour_of(row) < quiet_end:
                entry = before[device_of(row)]
                entry[0] += as_int(row["bytes_up"])
                entry[1] += as_int(row["bytes_down"])

    for device, (up, down, count) in sorted(
        by_device.items(), key=lambda kv: -(kv[1][0] + kv[1][1])
    ):
        was_up, was_down = before.get(device, [0, 0])
        total = up + down
        was = was_up + was_down
        if total == 0:
            continue
        severity = "low"
        detail = "%d flow(s)" % count
        if was and total > was * 2:
            severity = "medium"
            detail = "%d flow(s), before it was %s in the same hours" % (count, human(was))
        elif not was and total > 1024 * 1024 and device in known_devices:
            # only a device that was quiet before can be loud now
            severity = "medium"
            detail = "%d flow(s), it has never done that" % count
        elif not was and total > 1024 * 1024:
            detail = "%d flow(s), the device is new, there is nothing to compare it with" % count
        findings.append(
            Finding(
                "night",
                severity,
                "%s moved %s between %02d:00 and %02d:00"
                % (device, human(total), quiet_start, quiet_end),
                detail,
            )
        )
    return findings


def find_new_destinations(rows, baseline):
    """Destinations that were not there before.

    A device that was not in the file of yesterday is new itself.  Everything
    it does is new too, and that is not worth a report - it only becomes
    worth one when the device starts to do something it did not do before.
    """
    findings = []
    if not baseline:
        return findings
    known = set()
    known_ports = set()
    known_devices = devices_of(baseline)
    for row in baseline:
        known.add(destination_of(row))
        known_ports.add(port_of(row))
    seen = set()
    for row in rows:
        if device_of(row) not in known_devices:
            # the device is new, everything it does is new
            continue
        dest = destination_of(row)
        port = port_of(row)
        if dest in seen:
            continue
        seen.add(dest)
        if dest in known:
            continue
        unusual = port and (port not in KNOWN_PORTS or port > HIGH_PORT)
        findings.append(
            Finding(
                "new",
                "high" if unusual else "low",
                "%s is talking to %s:%s, it never did that before"
                % (device_of(row), row.get("dst_ip"), row.get("dst_port")),
                "the port is not one of the usual ones" if unusual else "",
            )
        )
    return findings


def find_odd_ports(rows):
    """Ports that a phone has no reason to use."""
    findings = []
    ports = Counter()
    where = {}
    for row in rows:
        port = port_of(row)
        if not port or port in KNOWN_PORTS:
            continue
        ports[port] += 1
        where.setdefault(
            port, (row.get("dst_ip"), row.get("time_of_day"), device_of(row),
                   as_int(row["bytes_up"]))
        )
    for port, count in ports.most_common(10):
        ip, at, device, up = where[port]
        severity = "high" if port > HIGH_PORT else "medium"
        findings.append(
            Finding(
                "port",
                severity,
                "%s uses port %d, which is not a normal service" % (device, port),
                "%d flow(s) to %s, first at %s, %s uploaded" % (count, ip, at, human(up)),
            )
        )
    return findings


def find_talkers(rows, baseline):
    """A device that suddenly became talkative."""
    findings = []
    if not baseline:
        return findings
    now = defaultdict(lambda: [0, 0])
    before = defaultdict(lambda: [0, 0])
    for row in rows:
        entry = now[device_of(row)]
        entry[0] += 1
        entry[1] += as_int(row["bytes_down"]) + as_int(row["bytes_up"])
    for row in baseline:
        entry = before[device_of(row)]
        entry[0] += 1
        entry[1] += as_int(row["bytes_down"]) + as_int(row["bytes_up"])
    for device, (count, size) in now.items():
        was_count, was_size = before.get(device, [0, 0])
        if count < 20 or was_count == 0:
            continue
        if count > was_count * 3:
            findings.append(
                Finding(
                    "talker",
                    "medium",
                    "%s opened %d connections, before it was %d" % (device, count, was_count),
                    "%s in total" % human(size),
                )
            )
    return findings


# -- the report -------------------------------------------------------------
def collect_findings(rows, baseline, options):
    findings = []
    findings += find_streams(rows, options.stream_rate, options.stream_seconds)
    findings += find_night_traffic(
        rows, options.quiet_start, options.quiet_end, baseline
    )
    findings += find_new_destinations(rows, baseline)
    findings += find_odd_ports(rows)
    findings += find_talkers(rows, baseline)
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 3))
    return findings


def verdict(findings):
    """One line: is there something to worry about?"""
    high = sum(1 for f in findings if f.severity == "high")
    medium = sum(1 for f in findings if f.severity == "medium")
    low = sum(1 for f in findings if f.severity == "low")
    if high:
        return "%d THING(S) TO WORRY ABOUT" % high
    if medium:
        return "%d THING(S) WORTH A LOOK" % medium
    if low:
        return "nothing serious, %d small thing(s)" % low
    return "NOTHING TO WORRY ABOUT"


def report_text(rows, findings, options, baseline=None):
    """The report, as text.  The same text the command line prints."""
    lines = []

    if not rows:
        return "the file is empty\n"

    total_up = sum(as_int(r["bytes_up"]) for r in rows)
    total_down = sum(as_int(r["bytes_down"]) for r in rows)
    active = [r for r in rows if r.get("state") == "active"]
    times = sorted(r.get("time_of_day") for r in rows if r.get("time_of_day"))

    lines.append("=" * 72)
    lines.append("  traffic-inspector  -  %d flow(s), %s up, %s down"
                 % (len(rows), human(total_up), human(total_down)))
    if times:
        lines.append("  between %s and %s, %d still open"
                     % (times[0], times[-1], len(active)))
    lines.append("=" * 72)
    lines.append("")
    lines.append("  %s" % verdict(findings))
    lines.append("")

    if findings:
        for number, finding in enumerate(findings, 1):
            lines.append("  %d. [%s] %s"
                         % (number, finding.severity.upper(), finding.title))
            if finding.detail:
                lines.append("       %s" % finding.detail)
        lines.append("")
    else:
        lines.append("  No stream that never stops, no traffic in the quiet hours, no")
        lines.append("  destination that was not there before, no odd port.")
        lines.append("")

    # -- the devices -------------------------------------------------------
    lines.append("-- the devices ----------------------------------------------------")
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
        name = device[:24]
        if baseline is not None and device not in devices_of(baseline):
            # a device that was not there yesterday: there is nothing to
            # compare it with, so it is marked as new
            name = "%s (new)" % device[:16]
        lines.append(
            "  %-24s %4d flow(s)  %-10s  up %-10s  %s -> %s"
            % (name, count, human(size), human(up),
               (start or "?")[:19], (end or "still open")[:19])
        )
    lines.append("")

    # -- the destinations --------------------------------------------------
    lines.append("-- the destinations -----------------------------------------------")
    by_dest = defaultdict(lambda: [0, 0, 0])
    for row in rows:
        entry = by_dest[destination_of(row)]
        entry[0] += as_int(row["bytes_down"])
        entry[1] += as_int(row["bytes_up"])
        entry[2] += 1
    for dest, (down, up, count) in sorted(
        by_dest.items(), key=lambda kv: -(kv[1][0] + kv[1][1])
    )[:15]:
        lines.append(
            "  %-40s %4d flow(s)  up %-10s down %s"
            % (dest[:40], count, human(up), human(down))
        )
    lines.append("")

    # -- the ports ---------------------------------------------------------
    lines.append("-- the ports and the services -------------------------------------")
    by_port = defaultdict(lambda: [0, 0, ""])
    for row in rows:
        entry = by_port[row.get("dst_port") or "?"]
        entry[0] += as_int(row["bytes_down"]) + as_int(row["bytes_up"])
        entry[1] += 1
        entry[2] = row.get("service") or ""
    for port, (size, count, service) in sorted(by_port.items(), key=lambda kv: -kv[1][0])[:15]:
        lines.append("  port %-8s %-16s %4d flow(s)  %s"
                     % (port, service, count, human(size)))
    lines.append("")

    # -- the hours ---------------------------------------------------------
    lines.append("-- the hours of the day -------------------------------------------")
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
            mark = "  <- quiet" if options.quiet_start <= hour < options.quiet_end else ""
            lines.append("  %02d:00  %4d %s%s" % (hour, count, bar, mark))
    lines.append("")

    return "\n".join(lines)


def load(path):
    """The rows of a CSV file."""
    try:
        with open(path, newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            missing = set(FIELDS) - set(reader.fieldnames or [])
            if missing:
                raise ReportError(
                    "the file is missing the columns: %s" % ", ".join(sorted(missing))
                )
            return [dict(row) for row in reader]
    except OSError as exc:
        raise ReportError("the file cannot be read: %s" % exc)


def find_baseline(options):
    """The file to compare against.

    ``--baseline auto`` looks for the archive of yesterday, the server keeps
    one file per day.
    """
    if not options.baseline:
        return None
    if options.baseline != "auto":
        return options.baseline if os.path.exists(options.baseline) else None
    yesterday = (datetime.now().date() - timedelta(days=1)).isoformat()
    folder = os.path.dirname(os.path.abspath(options.csv))
    name = os.path.splitext(os.path.basename(options.csv))[0]
    for candidate in (
        os.path.join(folder, "%s-%s.csv" % (name, yesterday)),
        os.path.join(folder, "traffic-%s.csv" % yesterday),
    ):
        if os.path.exists(candidate):
            return candidate
    return None


def load_baseline(options):
    """The rows of the file to compare against, or None.

    ``--baseline auto`` looks for the archive of yesterday, the server keeps
    one file per day.
    """
    path = find_baseline(options)
    if not path:
        return None
    try:
        return load(path)
    except ReportError:
        return None


def make_report(csv_path, baseline_path=None, options=None):
    """The report of a CSV file, as text.

    ``baseline_path`` is the file of an earlier day, when there is one.
    """
    if options is None:
        options = default_options(csv_path)
    rows = load(csv_path)
    baseline = None
    if baseline_path and os.path.exists(baseline_path):
        try:
            baseline = load(baseline_path)
        except ReportError:
            baseline = None
    findings = collect_findings(rows, baseline, options)
    return report_text(rows, findings, options, baseline)


def default_options(csv_path="traffic.csv", **kwargs):
    """The options of the analysis, with the usual values."""
    options = parse_args(["--csv", csv_path])
    for key, value in kwargs.items():
        setattr(options, key, value)
    return options


def reports_folder(csv_path, folder=None):
    """Where the reports are kept.

    By default it is a ``reports`` folder next to the CSV file, so the
    reports of the day end up together and the old ones are kept.
    """
    if folder:
        return str(folder)
    base = os.path.dirname(os.path.abspath(csv_path))
    return os.path.join(base, "reports")


def save_report(text, csv_path, folder=None, when=None):
    """Write the report into the reports folder and return the path.

    The name holds the time, so the reports can be put in order and the
    old ones are not overwritten.
    """
    folder = reports_folder(csv_path, folder)
    try:
        os.makedirs(folder, exist_ok=True)
    except OSError:
        return None
    when = when or datetime.now()
    name = "report-%s.txt" % when.strftime("%Y-%m-%d-%H%M%S")
    path = os.path.join(folder, name)
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
    except OSError:
        return None
    return path


def parse_args(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description="analyse a traffic-inspector CSV file")
    parser.add_argument("--csv", default="traffic.csv", help="CSV file to read")
    parser.add_argument(
        "--baseline",
        default=None,
        help="an older CSV, only what is new compared to it is reported "
             "(use 'auto' for the archive of yesterday)",
    )
    parser.add_argument(
        "--quiet-start", type=int, default=0, help="first hour of the quiet period (default 0)"
    )
    parser.add_argument(
        "--quiet-end", type=int, default=5, help="hour after the quiet period (default 5)"
    )
    parser.add_argument(
        "--stream-rate",
        type=float,
        default=15 * 1024,
        help="bytes per second that count as a stream (default 15 KB)",
    )
    parser.add_argument(
        "--stream-seconds",
        type=float,
        default=60.0,
        help="how long a flow has to last to be a stream (default 60)",
    )
    parser.add_argument(
        "--reports-dir",
        default=None,
        help="where the report is kept (default: a reports folder next to the csv)",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="do not write the report into the reports folder",
    )
    return parser.parse_args(argv)
