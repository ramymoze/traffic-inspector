import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.inspector import Inspector
from tools import analyze


class FakeFlow:
    def __init__(self, **kwargs):
        self.flow_id = kwargs.get("flow_id", 1)
        self.started_at = kwargs.get("started_at", 1700000000.0)
        self.ended_at = kwargs.get("ended_at")
        self.client_id = kwargs.get("client_id", "abc")
        self.device = kwargs.get("device", "pixel8-android")
        self.tunnel_src = kwargs.get("tunnel_src", "203.0.113.9")
        self.tunnel_src_port = kwargs.get("tunnel_src_port", 51234)
        self.src_ip = kwargs.get("src_ip", "10.8.0.1")
        self.src_port = kwargs.get("src_port", 52344)
        self.dst_ip = kwargs.get("dst_ip", "142.250.200.164")
        self.dst_port = kwargs.get("dst_port", 443)
        self.dst_name = kwargs.get("dst_name", "")
        self.proto_name = kwargs.get("proto_name", "TCP")
        self.service = kwargs.get("service", "https")
        self.bytes_up = kwargs.get("bytes_up", 120)
        self.bytes_down = kwargs.get("bytes_down", 4096)
        self.state = kwargs.get("state", "active")
        self.note = kwargs.get("note", "")


def test_the_file_of_the_day_is_kept_under_its_name(tmp_path):
    """When the day changes the file is archived, so there is a history."""
    path = tmp_path / "traffic.csv"
    inspector = Inspector(path)
    inspector.upsert(FakeFlow())
    inspector.maybe_write(force=True)
    assert path.exists()

    yesterday = datetime.date.today() - datetime.timedelta(days=1)
    inspector._day = yesterday
    inspector.maybe_write(force=True)

    archive = tmp_path / ("traffic-%s.csv" % yesterday.isoformat())
    assert archive.exists(), "the file of the day was not archived"
    assert "flow_id" in archive.read_text(encoding="utf-8")


def test_the_archive_of_yesterday_is_found(tmp_path):
    """--baseline auto looks for it."""
    path = tmp_path / "traffic.csv"
    path.write_text("flow_id,ts_start\n1,2026-10-21T00:00:00+00:00\n")
    yesterday = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
    (tmp_path / ("traffic-%s.csv" % yesterday)).write_text(
        "flow_id,ts_start\n1,2026-10-20T00:00:00+00:00\n"
    )

    options = analyze.parse_args(["--csv", str(path), "--baseline", "auto"])
    found = analyze.find_baseline(options)
    assert found is not None
    assert found.endswith("traffic-%s.csv" % yesterday)


def test_auto_finds_nothing_when_there_is_no_archive(tmp_path):
    path = tmp_path / "traffic.csv"
    path.write_text("flow_id,ts_start\n1,2026-10-21T00:00:00+00:00\n")
    options = analyze.parse_args(["--csv", str(path), "--baseline", "auto"])
    assert analyze.find_baseline(options) is None


def _write_csv(path, rows=1):
    """A csv file with all the columns the inspector writes."""
    import csv

    from server.inspector import FIELDS

    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        for number in range(rows):
            writer.writerow({
                "flow_id": number,
                "ts_start": "2026-10-21T00:00:00+00:00",
                "ts_end": "2026-10-21T00:05:00+00:00",
                "time_of_day": "00:00:00",
                "duration_s": "300.000",
                "client_id": "abc",
                "device": "pixel8-android",
                "tunnel_src": "203.0.113.9",
                "tunnel_src_port": "51234",
                "src_ip": "10.8.0.1",
                "src_port": "52344",
                "dst_ip": "142.250.200.164",
                "dst_port": "443",
                "dst_name": "",
                "proto": "TCP",
                "service": "https",
                "bytes_up": "120",
                "bytes_down": "4096",
                "state": "closed",
                "note": "",
            })


def test_the_command_line_survives_the_baseline(tmp_path, capsys):
    """The baseline is a file of rows, not the name of a file."""
    path = tmp_path / "traffic.csv"
    _write_csv(path)
    yesterday = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
    _write_csv(tmp_path / ("traffic-%s.csv" % yesterday))

    code = analyze.main(["--csv", str(path), "--baseline", "auto"])
    assert code in (0, 1)
    assert "traffic-inspector" in capsys.readouterr().out


def test_the_report_is_kept_in_the_reports_folder(tmp_path, capsys):
    """Every report is written next to the csv, in the reports folder."""
    path = tmp_path / "traffic.csv"
    _write_csv(path)

    analyze.main(["--csv", str(path)])

    saved = sorted((tmp_path / "reports").glob("report-*.txt"))
    assert saved, "the report was not kept"
    assert "traffic-inspector" in saved[-1].read_text(encoding="utf-8")


def test_the_reports_folder_can_be_chosen(tmp_path, capsys):
    path = tmp_path / "traffic.csv"
    _write_csv(path)
    folder = tmp_path / "somewhere-else"

    analyze.main(["--csv", str(path), "--reports-dir", str(folder)])

    assert list(folder.glob("report-*.txt")), "the report was not kept there"
