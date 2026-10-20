import csv

from server.inspector import FIELDS, Inspector, service_name


class FakeFlow:
    def __init__(self, **kwargs):
        self.flow_id = kwargs.get("flow_id", 1)
        self.started_at = kwargs.get("started_at", 1700000000.0)
        self.ended_at = kwargs.get("ended_at")
        self.client_id = kwargs.get("client_id", "abc123")
        self.device = kwargs.get("device", "pixel8-android")
        self.tunnel_src = kwargs.get("tunnel_src", "203.0.113.9")
        self.tunnel_src_port = kwargs.get("tunnel_src_port", 51234)
        self.src_ip = kwargs.get("src_ip", "10.8.0.2")
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


def test_service_name_known_port():
    assert service_name(80, "TCP") == "http"
    assert service_name(443, "TCP") == "https"


def test_service_name_unknown_port():
    assert "Unknown" in service_name(37215, "TCP")


def test_the_csv_has_the_expected_columns(tmp_path):
    path = tmp_path / "traffic.csv"
    inspector = Inspector(path)
    inspector.upsert(FakeFlow())
    inspector.maybe_write(force=True)

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == FIELDS
        rows = list(reader)
    assert len(rows) == 1
    row = rows[0]
    assert row["dst_ip"] == "142.250.200.164"
    assert row["dst_port"] == "443"
    assert row["src_ip"] == "10.8.0.2"
    assert row["service"] == "https"
    assert row["device"] == "pixel8-android"
    assert row["bytes_up"] == "120"
    assert row["bytes_down"] == "4096"
    assert row["state"] == "active"
    assert row["time_of_day"]


def test_upsert_refreshes_the_row(tmp_path):
    path = tmp_path / "traffic.csv"
    inspector = Inspector(path)
    inspector.upsert(FakeFlow(bytes_up=10))
    inspector.upsert(FakeFlow(bytes_up=999, state="closed", ended_at=1700000010.0))
    inspector.maybe_write(force=True)

    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    assert rows[0]["bytes_up"] == "999"
    assert rows[0]["state"] == "closed"
    assert rows[0]["ts_end"]


def test_the_file_is_rewritten_atomically(tmp_path):
    path = tmp_path / "traffic.csv"
    inspector = Inspector(path)
    inspector.upsert(FakeFlow())
    inspector.maybe_write(force=True)
    assert path.exists()
    # no temporary file must be left behind
    leftovers = [p.name for p in tmp_path.iterdir() if p.name != "traffic.csv"]
    assert leftovers == []
