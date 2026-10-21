import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.inspector import FIELDS
from tools import analyze

HEADER = ",".join(FIELDS)


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in FIELDS})


def a_row(**kwargs):
    row = {
        "flow_id": 1,
        "ts_start": "2026-10-20T02:14:33+00:00",
        "ts_end": "2026-10-20T02:18:33+00:00",
        "time_of_day": "02:14:33",
        "duration_s": "240.000",
        "client_id": "abc123",
        "device": "pixel8-android",
        "tunnel_src": "203.0.113.9",
        "tunnel_src_port": 51234,
        "src_ip": "10.8.0.1",
        "src_port": 52344,
        "dst_ip": "198.51.100.7",
        "dst_port": 8081,
        "dst_name": "",
        "proto": "TCP",
        "service": "Unknown (8081)",
        "bytes_up": 5242880,
        "bytes_down": 1024,
        "state": "closed",
        "note": "",
    }
    row.update(kwargs)
    return row


def test_a_long_upload_is_reported(tmp_path):
    path = tmp_path / "traffic.csv"
    write_csv(path, [a_row()])
    rows = analyze.load(str(path))
    args = analyze.parse_args(["--csv", str(path)])
    findings = analyze.collect_findings(rows, None, args)
    kinds = [f.kind for f in findings]
    assert "stream" in kinds
    stream = [f for f in findings if f.kind == "stream"][0]
    assert "198.51.100.7" in stream.title
    assert stream.severity == "high"


def test_a_small_upload_is_not_reported(tmp_path):
    path = tmp_path / "traffic.csv"
    write_csv(path, [a_row(bytes_up=100, duration_s=1.0)])
    rows = analyze.load(str(path))
    args = analyze.parse_args(["--csv", str(path)])
    findings = analyze.collect_findings(rows, None, args)
    assert "stream" not in [f.kind for f in findings]


def test_activity_in_the_quiet_hours_is_reported(tmp_path):
    path = tmp_path / "traffic.csv"
    write_csv(path, [a_row(bytes_up=2 * 1024 * 1024, time_of_day="03:20:00")])
    rows = analyze.load(str(path))
    args = analyze.parse_args(["--csv", str(path), "--quiet-mb", "1"])
    findings = analyze.collect_findings(rows, None, args)
    quiet = [f for f in findings if f.kind == "quiet"]
    assert quiet, "the traffic of the night was not reported"
    assert "pixel8-android" in quiet[0].title


def test_activity_outside_the_quiet_hours_is_not_reported(tmp_path):
    path = tmp_path / "traffic.csv"
    write_csv(path, [a_row(bytes_up=2 * 1024 * 1024, time_of_day="14:20:00")])
    rows = analyze.load(str(path))
    args = analyze.parse_args(["--csv", str(path), "--quiet-mb", "1"])
    findings = analyze.collect_findings(rows, None, args)
    assert "quiet" not in [f.kind for f in findings]


def test_a_destination_that_is_new_compared_to_the_baseline_is_reported(tmp_path):
    baseline = tmp_path / "before.csv"
    current = tmp_path / "now.csv"
    write_csv(baseline, [a_row(dst_ip="1.2.3.4", dst_port=443, service="https")])
    write_csv(current, [a_row(dst_ip="198.51.100.7", dst_port=8081)])

    rows = analyze.load(str(current))
    old = analyze.load(str(baseline))
    args = analyze.parse_args(["--csv", str(current)])
    findings = analyze.collect_findings(rows, old, args)
    new = [f for f in findings if f.kind == "new"]
    assert new, "the new destination was not reported"
    assert "198.51.100.7" in new[0].title


def test_a_destination_that_was_already_there_is_not_reported(tmp_path):
    baseline = tmp_path / "before.csv"
    current = tmp_path / "now.csv"
    write_csv(baseline, [a_row(dst_ip="198.51.100.7", dst_port=8081)])
    write_csv(current, [a_row(dst_ip="198.51.100.7", dst_port=8081)])

    rows = analyze.load(str(current))
    old = analyze.load(str(baseline))
    args = analyze.parse_args(["--csv", str(current)])
    findings = analyze.collect_findings(rows, old, args)
    assert "new" not in [f.kind for f in findings]


def test_an_unknown_port_is_reported(tmp_path):
    path = tmp_path / "traffic.csv"
    write_csv(path, [a_row(bytes_up=10, duration_s=1.0, dst_port=37215, service="Unknown (37215)")])
    rows = analyze.load(str(path))
    args = analyze.parse_args(["--csv", str(path)])
    findings = analyze.collect_findings(rows, None, args)
    ports = [f for f in findings if f.kind == "port"]
    assert ports, "the odd port was not reported"
    assert "37215" in ports[0].title


def test_the_report_runs(tmp_path, capsys):
    path = tmp_path / "traffic.csv"
    write_csv(path, [a_row()])
    assert analyze.main(["--csv", str(path)]) == 1  # a high finding
    out = capsys.readouterr().out
    assert "worth a look" in out
    assert "pixel8-android" in out


def test_the_exit_code_is_zero_when_nothing_is_wrong(tmp_path, capsys):
    path = tmp_path / "traffic.csv"
    write_csv(
        path,
        [a_row(bytes_up=10, duration_s=1.0, dst_port=443, service="https", time_of_day="12:00:00")],
    )
    assert analyze.main(["--csv", str(path), "--quiet-mb", "1000"]) == 0
