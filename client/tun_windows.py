"""The Windows TUN device.

Windows has no ``/dev/net/tun``, so the virtual network adapter comes from
**Wintun**, the small layer 3 driver that WireGuard uses.  It is a single
file, ``wintun.dll``.  Put it next to this file (``client/wintun.dll``) or
let the client fetch it::

    python -m client.tun_windows --download

The adapter is a layer 3 device: Windows puts the IP packets of the machine
into it, and whatever is written into it comes back as if it arrived from the
network.  That is the same contract as the Linux client, so the bridge does
not have to know the difference.

The routes are set up with ``netsh`` and ``route``, which need an elevated
prompt ("Run as administrator").

How the driver is used:

* the **session** belongs to one thread - the one that reads the packets.
  The session is opened and closed there, so it never outlives its thread.
* the packets that go the other way are written from the main thread.  That
  is allowed: the driver copies them into the ring buffer of the adapter and
  the operating system picks them up from there.
"""

import ctypes
import io
import os
import queue
import subprocess
import sys
import threading
import time
import urllib.request
import zipfile
from pathlib import Path

#: Where the driver is looked for.
LOOKED_AT = (
    Path(__file__).with_name("wintun.dll"),
    Path(__file__).with_name("vendor") / "wintun.dll",
)

#: The address of the tunnel interface.  The kernel uses it as the source of
#: everything that goes through the tunnel, so the inspector can show it.
DEFAULT_ADDRESS = "10.8.0.1/24"

#: How much the tunnel route wins against the routes of the network cards.
TUNNEL_METRIC = 5

#: Where the driver is downloaded from.
DOWNLOAD_URL = "https://www.wintun.net/builds/wintun-latest.zip"


# ---------------------------------------------------------------- the driver
def download(destination=None):
    """Fetch the driver and put it next to this file."""
    destination = Path(destination) if destination else LOOKED_AT[0]
    print("[*] Fetching the Wintun driver ...")
    with urllib.request.urlopen(DOWNLOAD_URL, timeout=120) as answer:
        payload = answer.read()
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        for name in archive.namelist():
            if name.lower().endswith("wintun.dll") and "x86-64" in name.lower():
                with archive.open(name) as source:
                    driver = source.read()
                break
        else:
            raise RuntimeError("the archive does not hold wintun.dll")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(driver)
    print("[+] The driver is at %s" % destination)
    return destination


def find_dll(path=None):
    """The driver, or None when it is not there."""
    if path:
        candidate = Path(path)
        return candidate if candidate.exists() else None
    for candidate in LOOKED_AT:
        if candidate.exists():
            return candidate
    return None


class DriverError(RuntimeError):
    """The driver said no."""


class _Driver:
    """The parts of ``wintun.dll`` that are used here."""

    def __init__(self, path):
        self.path = str(path)
        loader = getattr(ctypes, "WinDLL", ctypes.CDLL)
        try:
            library = loader(self.path, use_last_error=True)
        except OSError as exc:
            raise DriverError("cannot load %s: %s" % (self.path, exc))
        self.library = library

        library.WintunCreateAdapter.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_ulong,
        ]
        library.WintunCreateAdapter.restype = ctypes.c_void_p
        library.WintunCloseAdapter.argtypes = [ctypes.c_void_p]
        library.WintunCloseAdapter.restype = None
        library.WintunStartSession.argtypes = [ctypes.c_void_p]
        library.WintunStartSession.restype = ctypes.c_void_p
        library.WintunEndSession.argtypes = [ctypes.c_void_p]
        library.WintunEndSession.restype = None
        library.WintunReceivePacket.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ulong),
        ]
        library.WintunReceivePacket.restype = ctypes.c_void_p
        library.WintunSendPacket.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_ulong,
        ]
        library.WintunSendPacket.restype = ctypes.c_int

        for name in (
            "WintunCreateAdapter",
            "WintunCloseAdapter",
            "WintunStartSession",
            "WintunEndSession",
            "WintunReceivePacket",
            "WintunSendPacket",
        ):
            if not hasattr(library, name):
                raise DriverError("%s is missing from %s" % (name, self.path))

        # Wintun 0.14 can open an adapter that is already there, older
        # versions open it with CreateAdapter.
        self.has_open = hasattr(library, "WintunOpenAdapter")
        if self.has_open:
            library.WintunOpenAdapter.argtypes = [ctypes.c_wchar_p]
            library.WintunOpenAdapter.restype = ctypes.c_void_p

    # -- the errors ---------------------------------------------------------
    def _error(self, what):
        code = ctypes.get_last_error()
        if code:
            try:
                text = ctypes.FormatError(code)
            except Exception:
                text = "error %d" % code
            return DriverError("%s failed: %s" % (what, text))
        return DriverError("%s failed" % what)

    # -- the adapter --------------------------------------------------------
    def open_adapter(self, name):
        """The adapter with that name, created when it does not exist yet."""
        adapter = None
        if self.has_open:
            adapter = self.library.WintunOpenAdapter(name)
        if not adapter:
            adapter = self.library.WintunCreateAdapter(
                name, "traffic-inspector", None, 0
            )
            if not adapter:
                raise self._error("opening the adapter %s" % name)
        return adapter

    def close_adapter(self, adapter):
        if adapter:
            self.library.WintunCloseAdapter(adapter)

    # -- the session --------------------------------------------------------
    def start_session(self, adapter):
        session = self.library.WintunStartSession(adapter)
        if not session:
            raise self._error("starting the session")
        return session

    def end_session(self, session):
        if session:
            self.library.WintunEndSession(session)

    def receive(self, session):
        """One packet, or None when there is none (yet)."""
        size = ctypes.c_ulong(0)
        pointer = self.library.WintunReceivePacket(session, ctypes.byref(size))
        if not pointer:
            return None
        # the buffer belongs to the driver, it is only good until the next
        # call - so it is copied right away
        return ctypes.string_at(pointer, size.value)

    def send(self, session, data):
        buffer = ctypes.create_string_buffer(data, len(data))
        return bool(self.library.WintunSendPacket(session, buffer, len(data)))


class WintunTun:
    """The TUN adapter of Windows."""

    def __init__(self, name="ti0", dll=None):
        self.name = name
        self.dll_path = find_dll(dll)
        self.adapter = None
        self.session = None
        self.dropped = 0
        self._driver = None
        self._incoming = queue.Queue(maxsize=1024)
        self._wire = None
        self._running = False
        self._ended = False
        self._guard = threading.Lock()

    # -- the device ---------------------------------------------------------
    def open(self):
        if os.name != "nt":
            raise RuntimeError("the Wintun adapter is Windows only")
        if self.dll_path is None:
            raise RuntimeError(
                "wintun.dll is missing - run: python -m client.tun_windows --download"
            )
        self._driver = _Driver(self.dll_path)
        self.adapter = self._driver.open_adapter(self.name)
        self._running = True
        self._wire = threading.Thread(
            target=self._wire_loop, name="wintun-reader", daemon=True
        )
        self._wire.start()
        return self

    def _wire_loop(self):
        """The thread that owns the session and reads the packets."""
        try:
            self.session = self._driver.start_session(self.adapter)
        except DriverError:
            self.session = None
            return
        try:
            while self._running:
                packet = self._driver.receive(self.session)
                if packet is None:
                    # nothing yet - the driver waits for the next packet
                    time.sleep(0.002)
                    continue
                try:
                    self._incoming.put(packet)
                except queue.Full:
                    # the tunnel is too slow, better to lose a packet than
                    # to hold everything in memory
                    self.dropped += 1
        finally:
            with self._guard:
                if not self._ended and self.session:
                    self._driver.end_session(self.session)
                    self._ended = True
                self.session = None

    def read(self, size=65535, timeout=None):
        """One packet that came from Windows, or None."""
        try:
            return self._incoming.get(timeout=timeout)
        except queue.Empty:
            return None

    def write(self, data):
        """Give one packet to Windows."""
        with self._guard:
            session = self.session
        if session is None:
            return 0
        if not self._driver.send(session, data):
            return 0
        return len(data)

    def close(self):
        self._running = False
        with self._guard:
            if self.session and not self._ended:
                # this wakes the thread that waits for a packet
                self._driver.end_session(self.session)
                self._ended = True
        if self._wire is not None:
            self._wire.join(timeout=3)
            self._wire = None
        if self.adapter:
            self._driver.close_adapter(self.adapter)
            self.adapter = None


# ----------------------------------------------------------------- the routes
def _run(command, check=True):
    """Run a command and return its output."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(
            "%s failed: %s" % (command, (result.stderr or result.stdout).strip())
        )
    return result.stdout.strip()


def parse_default_route(text):
    """The gateway and the interface of the default route.

    ``route print`` says which way out of the machine goes, the tunnel has
    to stay reachable without the tunnel.
    """
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            return parts[2], parts[3]
    return None, None


def default_route():
    """The gateway Windows uses right now, and the interface it belongs to."""
    return parse_default_route(_run("route print -4", check=False))


def _netmask(bits):
    """The netmask of a prefix length, for example 24 -> 255.255.255.0."""
    mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
    return ".".join(str((mask >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def setup(name="ti0", address=DEFAULT_ADDRESS, server=None, dns=None):
    """Give the adapter an address and route the traffic into it.

    ``server`` is the address of the tunnel server.  It has to stay outside
    of the tunnel, otherwise the client would talk to itself.
    """
    ip, _, prefix = address.partition("/")
    mask = _netmask(int(prefix or 24))

    _run('netsh interface ip set address name="%s" source=static %s %s' % (name, ip, mask))
    # the tunnel has to win against the wifi and the ethernet
    _run(
        'netsh interface ipv4 set interface interface="%s" metric=%d'
        % (name, TUNNEL_METRIC),
        check=False,
    )

    gateway, _ = default_route()
    if server and gateway:
        # the tunnel server must stay reachable without the tunnel
        _run("route delete %s mask 255.255.255.255" % server, check=False)
        _run(
            "route add %s mask 255.255.255.255 %s metric 1" % (server, gateway)
        )

    # everything else goes into the tunnel
    _run(
        'netsh interface ipv4 add route 0.0.0.0/0 interface="%s" nexthop=%s metric=%d'
        % (name, ip, TUNNEL_METRIC)
    )

    if dns:
        # the resolver of the tunnel, so the names are looked up there too
        _run(
            'netsh interface ip set dns name="%s" source=static address=%s'
            % (name, dns)
        )
    return gateway


def teardown(name="ti0", address=DEFAULT_ADDRESS, server=None):
    """Take the routes away again."""
    ip = address.split("/")[0]
    _run(
        'netsh interface ipv4 delete route 0.0.0.0/0 interface="%s" nexthop=%s'
        % (name, ip),
        check=False,
    )
    if server:
        _run("route delete %s mask 255.255.255.255" % server, check=False)
    _run('netsh interface ip set dns name="%s" source=dhcp' % name, check=False)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--download" in argv:
        download()
        return 0
    print(__doc__)
    print("The driver is %s" % ("at %s" % find_dll() if find_dll() else "missing"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
