import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.inspector import FIELDS
from tools import analyze


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in FIELDS})


def a_row(**kwargs):
    row = {
        "flow_id": 1,
        "ts_start": "2026-10-21T02:14:33+00:00",
        "ts_end": "2026-10-21T02:19:33+00:00",
        "time_of_day": "02:14:33",
        "duration_s": "300.000",
        "client_id": "abc123",
        "device": "pixel8-android",
        "tunnel_src": "203.0.113.9",
        "tunnel_src_port": "51234",
        "src_ip": "10.8.0.1",
        "src_port": "52344",
        "dst_ip": "198.51.100.7",
        "dst_port": "8081",
        "dst_name": "",
        "proto": "TCP",
        "service": "Unknown (8081)",
        "bytes_up": "5242880",
        "bytes_down": "1024",
        "state": "closed",
        "note": "",
    }
    row.update(kwargs)
    return row


def options_for(path, **kwargs):
    options = analyze.parse_args(["--csv", path])
    for key, value in kwargs.items():
        setattr(options, key, value)
    return options


# -- the stream, the thing the whole project is about -----------------------
def test_an_upload_that_never_stops_is_reported(tmp_path):
    path = tmp_path / "traffic.csv"
    write_csv(path, [a_row()])
    rows = analyze.load(str(path))
    findings = analyze.collect_findings(rows, None, options_for(str(path)))
    streams = [f for f in findings if f.kind == "stream"]
    assert streams, "the stream was not reported"
    assert streams[0].severity == "high"
    assert "sending" in streams[0].title


def test_a_page_that_loads_quickly_is_not_a_stream(tmp_path):
    path = tmp_path / "traffic.csv"
    write_csv(
        path,
        [a_row(bytes_up="422", bytes_down="979512", duration_s="1.2")],
    )
    rows = analyze.load(str(path))
    findings = analyze.collect_findings(rows, None, options_for(str(path)))
    assert "stream" not in [f.kind for f in findings]


def test_a_short_burst_is_not_a_stream(tmp_path):
    path = tmp_path / "traffic.csv"
    write_csv(path, [a_row(bytes_up="5242880", duration_s="2.0")])
    rows = analyze.load(str(path))
    findings = analyze.collect_findings(rows, None, options_for(str(path)))
    assert "stream" not in [f.kind for f in findings]


# -- the quiet hours --------------------------------------------------------
def test_traffic_in_the_quiet_hours_is_reported(tmp_path):
    path = tmp_path / "traffic.csv"
    write_csv(path, [a_row(time_of_day="02:30:00", bytes_up="2097152")])
    rows = analyze.load(str(path))
    findings = analyze.collect_findings(rows, None, options_for(str(path)))
    night = [f for f in findings if f.kind == "night"]
    assert night, "the traffic of the night was not reported"
    assert "00:00 and 05:00" in night[0].title


def test_traffic_in_the_day_is_not_reported(tmp_path):
    path = tmp_path / "traffic.csv"
    write_csv(path, [a_row(time_of_day="14:30:00", bytes_up="2097152")])
    rows = analyze.load(str(path))
    findings = analyze.collect_findings(rows, None, options_for(str(path)))
    assert "night" not in [f.kind for f in findings]


def test_more_traffic_at_night_than_before_is_worse(tmp_path):
    path = tmp_path / "now.csv"
    baseline = tmp_path / "before.csv"
    write_csv(baseline, [a_row(time_of_day="02:30:00", bytes_up="1024")])
    write_csv(path, [a_row(time_of_day="02:30:00", bytes_up="2097152")])
    rows = analyze.load(str(path))
    old = analyze.load(str(baseline))
    findings = analyze.collect_findings(rows, old, options_for(str(path)))
    night = [f for f in findings if f.kind == "night"]
    assert night
    assert night[0].severity == "medium"
    assert "never" in night[0].detail or "before" in night[0].detail


# -- the unknown destination -----------------------------------------------
def test_a_destination_that_was_not_there_before_is_reported(tmp_path):
    path = tmp_path / "now.csv"
    baseline = tmp_path / "before.csv"
    write_csv(baseline, [a_row(dst_ip="1.2.3.4", dst_port=443, service="https")])
    write_csv(path, [a_row(dst_ip="198.51.100.7", dst_port=8081)])
    rows = analyze.load(str(path))
    old = analyze.load(str(baseline))
    findings = analyze.collect_findings(rows, old, options_for(str(path)))
    new = [f for f in findings if f.kind == "new"]
    assert new, "the new destination was not reported"
    assert new[0].severity == "high", "an odd port should be reported as high"


def test_a_destination_that_was_already_there_is_not_reported(tmp_path):
    path = tmp_path / "now.csv"
    baseline = tmp_path / "before.csv"
    write_csv(baseline, [a_row(dst_ip="198.51.100.7", dst_port=8081)])
    write_csv(path, [a_row(dst_ip="198.51.100.7", dst_port=8081)])
    rows = analyze.load(str(path))
    old = analyze.load(str(baseline))
    findings = analyze.collect_findings(rows, old, options_for(str(path)))
    assert "new" not in [f.kind for f in findings]


# -- the device that is new -------------------------------------------------
def test_a_new_device_does_not_make_everything_look_new(tmp_path):
    """A device that was not there yesterday: everything it does is new.

    That is not something to report, or the report cries wolf every time a
    phone is connected.
    """
    path = tmp_path / "now.csv"
    baseline = tmp_path / "before.csv"
    write_csv(baseline, [a_row(device="pixel8-android", dst_ip="1.2.3.4", dst_port=443)])
    write_csv(
        path,
        [
            a_row(device="new-phone", dst_ip="198.51.100.7", dst_port=8081),
            a_row(device="new-phone", dst_ip="203.0.113.5", dst_port=443),
        ],
    )
    rows = analyze.load(str(path))
    old = analyze.load(str(baseline))
    findings = analyze.collect_findings(rows, old, options_for(str(path)))
    assert "new" not in [f.kind for f in findings], "the new device was reported"


def test_a_device_that_was_there_and_starts_something_new_is_reported(tmp_path):
    """The same device, but a destination it never used."""
    path = tmp_path / "now.csv"
    baseline = tmp_path / "before.csv"
    write_csv(baseline, [a_row(device="pixel8-android", dst_ip="1.2.3.4", dst_port=443)])
    write_csv(
        path,
        [
            a_row(device="pixel8-android", dst_ip="1.2.3.4", dst_port=443),
            a_row(device="pixel8-android", dst_ip="198.51.100.7", dst_port=8081),
        ],
    )
    rows = analyze.load(str(path))
    old = analyze.load(str(baseline))
    findings = analyze.collect_findings(rows, old, options_for(str(path)))
    new = [f for f in findings if f.kind == "new"]
    assert new, "the new destination of the known device was not reported"


def test_the_night_traffic_of_a_new_device_is_not_suspicious(tmp_path):
    """There is nothing to compare a new device with."""
    path = tmp_path / "now.csv"
    baseline = tmp_path / "before.csv"
    write_csv(baseline, [a_row(device="pixel8-android")])
    write_csv(path, [a_row(device="new-phone", bytes_up="5242880")])
    rows = analyze.load(str(path))
    old = analyze.load(str(baseline))
    findings = analyze.collect_findings(rows, old, options_for(str(path)))
    night = [f for f in findings if f.kind == "night"]
    assert night, "the night traffic was not reported at all"
    assert night[0].severity == "low", "a new device must not look suspicious"
    assert "new" in night[0].detail


def test_a_new_device_is_marked_in_the_report(tmp_path):
    path = tmp_path / "now.csv"
    baseline = tmp_path / "before.csv"
    write_csv(baseline, [a_row(device="pixel8-android")])
    write_csv(path, [a_row(device="new-phone")])
    rows = analyze.load(str(path))
    old = analyze.load(str(baseline))
    findings = analyze.collect_findings(rows, old, options_for(str(path)))
    text = analyze.report_text(rows, findings, options_for(str(path)), old)
    assert "new-phone (new)" in text


def test_the_ports_a_phone_really_uses_are_not_odd(tmp_path):
    """The push of google and the stun of the calls are normal."""
    path = tmp_path / "traffic.csv"
    write_csv(
        path,
        [
            a_row(dst_port=5228, service="Unknown (5228)"),
            a_row(dst_port=5222, service="Unknown (5222)"),
            a_row(dst_port=3478, service="Unknown (3478)"),
        ],
    )
    rows = analyze.load(str(path))
    findings = analyze.collect_findings(rows, None, options_for(str(path)))
    assert "port" not in [f.kind for f in findings], "a normal port was called odd"


# -- the odd port -----------------------------------------------------------
def test_a_port_that_is_not_a_service_is_reported(tmp_path):
    path = tmp_path / "traffic.csv"
    write_csv(path, [a_row(dst_port=37215, service="Unknown (37215)")])
    rows = analyze.load(str(path))
    findings = analyze.collect_findings(rows, None, options_for(str(path)))
    ports = [f for f in findings if f.kind == "port"]
    assert ports, "the odd port was not reported"
    assert "37215" in ports[0].title


def test_a_normal_port_is_not_reported(tmp_path):
    path = tmp_path / "traffic.csv"
    write_csv(path, [a_row(dst_port=443, service="https", bytes_up="100", duration_s="1")])
    rows = analyze.load(str(path))
    findings = analyze.collect_findings(rows, None, options_for(str(path)))
    assert "port" not in [f.kind for f in findings]


# -- the verdict ------------------------------------------------------------
def test_the_verdict_is_calm_when_there_is_nothing(tmp_path):
    path = tmp_path / "traffic.csv"
    write_csv(
        path,
        [a_row(dst_port=443, service="https", bytes_up="100", duration_s="1",
                time_of_day="14:00:00")],
    )
    rows = analyze.load(str(path))
    findings = analyze.collect_findings(rows, None, options_for(str(path)))
    assert analyze.verdict(findings) == "NOTHING TO WORRY ABOUT"


def test_the_verdict_says_something_is_wrong(tmp_path):
    path = tmp_path / "traffic.csv"
    write_csv(path, [a_row()])
    rows = analyze.load(str(path))
    findings = analyze.collect_findings(rows, None, options_for(str(path)))
    assert "WORRY" in analyze.verdict(findings)


def test_the_exit_code_is_one_when_something_is_wrong(tmp_path):
    path = tmp_path / "traffic.csv"
    write_csv(path, [a_row()])
    assert analyze.main(["--csv", str(path)]) == 1


def test_the_exit_code_is_zero_when_all_is_well(tmp_path):
    path = tmp_path / "traffic.csv"
    write_csv(
        path,
        [a_row(dst_port=443, service="https", bytes_up="100", duration_s="1",
                time_of_day="14:00:00")],
    )
    assert analyze.main(["--csv", str(path)]) == 0

