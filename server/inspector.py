"""Flow inspector: keeps a CSV file describing every flow the server saw.

The file is rewritten atomically whenever something changed, so it is always
readable and always up to date - you can ``cat`` it while the server is
running and see the flow that is happening right now.

One row per flow, written when the flow is created and refreshed while it is
alive, so a long running flow (a webcam upload, for example) shows up in the
file while it is still going.
"""

import csv
import os
import socket
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path

FIELDS = [
    "flow_id",
    "ts_start",
    "ts_end",
    "time_of_day",
    "duration_s",
    "client_id",
    "device",
    "tunnel_src",
    "tunnel_src_port",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "dst_name",
    "proto",
    "service",
    "bytes_up",
    "bytes_down",
    "state",
    "note",
]


def service_name(port, proto_name):
    """Resolve a port to a well known service name, best effort."""
    if not port:
        return ""
    try:
        return socket.getservbyport(int(port), proto_name.lower())
    except (OSError, ValueError, TypeError):
        return "Unknown (%s)" % port


def _iso(timestamp):
    if not timestamp:
        return ""
    return datetime.fromtimestamp(timestamp).astimezone().isoformat(timespec="seconds")


def _time_of_day(timestamp):
    if not timestamp:
        return ""
    return datetime.fromtimestamp(timestamp).astimezone().strftime("%H:%M:%S")


class Inspector:
    """Collects flow rows and writes them to ``path`` as CSV."""

    def __init__(self, path="traffic.csv", flush_interval=1.0, enabled=True):
        self.path = Path(path)
        self.flush_interval = flush_interval
        self.enabled = enabled
        self._rows = {}
        self._order = []
        self._dirty = False
        self._last_write = 0.0
        self._lock = threading.RLock()

    # -- collection --------------------------------------------------------
    def upsert(self, flow):
        """Insert or refresh the row of ``flow``."""
        if not self.enabled:
            return
        with self._lock:
            row = self._row_for(flow)
            key = (row["client_id"], row["flow_id"])
            if key not in self._rows:
                self._order.append(key)
            self._rows[key] = row
            self._dirty = True

    def remove(self, key):
        with self._lock:
            if key in self._rows:
                del self._rows[key]
                self._order.remove(key)
                self._dirty = True

    def rows(self):
        with self._lock:
            return [dict(self._rows[key]) for key in self._order if key in self._rows]

    def _row_for(self, flow):
        started = getattr(flow, "started_at", None) or time.time()
        ended = getattr(flow, "ended_at", None)
        now = time.time()
        end_ref = ended if ended else now
        state = getattr(flow, "state", "active")
        # everything is stored as text, exactly like the CSV file holds it
        return {
            "flow_id": str(getattr(flow, "flow_id", "")),
            "ts_start": _iso(started),
            "ts_end": _iso(ended),
            "time_of_day": _time_of_day(started),
            "duration_s": "%.3f" % max(0.0, end_ref - started),
            "client_id": str(getattr(flow, "client_id", "")),
            "device": str(getattr(flow, "device", "") or ""),
            "tunnel_src": str(getattr(flow, "tunnel_src", "")),
            "tunnel_src_port": str(getattr(flow, "tunnel_src_port", "")),
            "src_ip": str(getattr(flow, "src_ip", "") or ""),
            "src_port": str(getattr(flow, "src_port", "") or ""),
            "dst_ip": str(getattr(flow, "dst_ip", "") or ""),
            "dst_port": str(getattr(flow, "dst_port", "") or ""),
            "dst_name": str(getattr(flow, "dst_name", "") or ""),
            "proto": str(getattr(flow, "proto_name", "")),
            "service": str(getattr(flow, "service", "") or ""),
            "bytes_up": str(getattr(flow, "bytes_up", 0)),
            "bytes_down": str(getattr(flow, "bytes_down", 0)),
            "state": str(state),
            "note": str(getattr(flow, "note", "") or ""),
        }

    # -- writing -----------------------------------------------------------
    def maybe_write(self, force=False):
        """Write the file if something changed and the interval elapsed."""
        with self._lock:
            if not self.enabled or not self._dirty:
                return False
            now = time.time()
            if not force and (now - self._last_write) < self.flush_interval:
                return False
            self._write_locked()
            return True

    def _write_locked(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = tempfile.NamedTemporaryFile(
            "w",
            newline="",
            encoding="utf-8",
            dir=str(self.path.parent),
            prefix=self.path.name + ".",
            suffix=".tmp",
            delete=False,
        )
        tmp_name = handle.name
        try:
            with handle:
                writer = csv.DictWriter(handle, fieldnames=FIELDS, extrasaction="ignore")
                writer.writeheader()
                for key in self._order:
                    row = self._rows.get(key)
                    if row is not None:
                        writer.writerow(row)
            os.replace(tmp_name, str(self.path))
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise
        self._dirty = False
        self._last_write = time.time()
