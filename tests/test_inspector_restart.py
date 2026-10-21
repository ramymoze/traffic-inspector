import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.inspector import FIELDS, Inspector


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


def test_the_rows_survive_a_restart_of_the_server(tmp_path):
    """The file holds the whole day, not only what this process has seen.

    Without this a device looks new every time the server comes back, and
    the report says that everything it does is new.
    """
    path = tmp_path / "traffic.csv"

    first = Inspector(path)
    first.upsert(FakeFlow(flow_id=1, device="rmx3687"))
    first.maybe_write(force=True)


    # the server is started again
    second = Inspector(path)
    rows = second.rows()
    assert len(rows) == 1, "the rows of the first server were lost"
    assert rows[0]["device"] == "rmx3687"

    # and the new server adds its own rows
    second.upsert(FakeFlow(flow_id=2, device="rmx3687"))
    second.maybe_write(force=True)


    with open(path, newline="", encoding="utf-8") as handle:
        written = list(csv.DictReader(handle))
    assert len(written) == 2, "the file does not hold both flows"


def test_the_device_stays_known_after_a_restart(tmp_path):
    """The report compares with the devices the file knows about."""
    from server import report as report_module

    path = tmp_path / "traffic.csv"
    first = Inspector(path)
    first.upsert(FakeFlow(flow_id=1, device="rmx3687", dst_ip="1.2.3.4"))
    first.maybe_write(force=True)


    second = Inspector(path)
    rows = second.rows()
    assert report_module.devices_of(rows) == {"rmx3687"}

