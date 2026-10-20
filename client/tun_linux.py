"""The Linux TUN device.

The TUN device is a virtual network interface: whatever the kernel sends to
it comes out of a file descriptor, and whatever is written to that descriptor
comes back into the kernel as if it arrived from the network.

The client does not get a packet information header (IFF_NO_PI), so the bytes
on the descriptor are exactly the IP packet, which is what the bridge
expects.
"""

import fcntl
import os
import struct
import subprocess

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

#: The address of the tunnel interface.  The kernel uses it as the source of
#: everything that goes through the tunnel, so the inspector can show it.
DEFAULT_ADDRESS = "10.8.0.1/24"


def _run(command, check=True):
    """Run a command and return its output."""
    result = subprocess.run(
        command, shell=True, capture_output=True, text=True
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            "%s failed: %s" % (command, (result.stderr or result.stdout).strip())
        )
    return result.stdout.strip()


class LinuxTun:
    """A TUN interface in layer 3 mode."""

    def __init__(self, name="ti0"):
        self.name = name
        self.fd = None

    def open(self):
        self.fd = os.open("/dev/net/tun", os.O_RDWR)
        ifr = struct.pack("16sH22s", self.name.encode(), IFF_TUN | IFF_NO_PI, b"")
        fcntl.ioctl(self.fd, TUNSETIFF, ifr)
        return self

    def read(self, size=65535):
        """Read one IP packet, or None when there is nothing."""
        try:
            return os.read(self.fd, size)
        except BlockingIOError:
            return None
        except OSError:
            return None

    def write(self, data):
        """Write one IP packet back into the kernel."""
        return os.write(self.fd, data)

    def close(self):
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None


def default_gateway():
    """The gateway the kernel uses right now, or None."""
    output = _run("ip route show default", check=False)
    for line in output.splitlines():
        parts = line.split()
        if parts and parts[0] == "default" and "via" in parts:
            return parts[parts.index("via") + 1]
    return None


def _directly_connected(address):
    """True when the address is on the local network and needs no gateway."""
    output = _run("ip route get %s" % address, check=False)
    return " via " not in output


def setup(name="ti0", address=DEFAULT_ADDRESS, server=None, dns=None):
    """Create the interface and route the traffic into it.

    ``server`` is the address of the tunnel server.  It has to stay outside
    of the tunnel, otherwise the client would talk to itself.
    """
    _run("ip link delete %s" % name, check=False)
    _run("ip tuntap add dev %s mode tun" % name)
    _run("ip addr replace %s dev %s" % (address, name))
    _run("ip link set %s up" % name)

    # The reverse path check compares the address a packet came from with
    # the route back to it.  With the tunnel in front of the default route
    # the two do not match any more, and the answers of the internet would
    # be dropped.  The loose mode is enough.
    _run("sysctl -w net.ipv4.conf.all.rp_filter=2", check=False)
    _run("sysctl -w net.ipv4.conf.default.rp_filter=2", check=False)
    _run("sysctl -w net.ipv4.conf.%s.rp_filter=2" % name, check=False)

    gateway = default_gateway()
    if server and gateway and not _directly_connected(server):
        # the tunnel server must stay reachable without the tunnel
        _run(
            "ip route replace %s/32 via %s dev %s"
            % (server, gateway, _primary_device())
        )

    # everything else goes into the tunnel.  Two half routes are enough and
    # they leave the old default route in place as a fallback.
    _run("ip route replace 0.0.0.0/1 dev %s" % name)
    _run("ip route replace 128.0.0.0/1 dev %s" % name)

    if dns:
        _write_resolv(dns)
    return gateway


def _primary_device():
    output = _run("ip route show default", check=False)
    for line in output.splitlines():
        parts = line.split()
        if parts and parts[0] == "default" and "dev" in parts:
            return parts[parts.index("dev") + 1]
    return "eth0"


def _write_resolv(nameservers):
    """Point the resolver at a public resolver.

    systemd-resolved owns /etc/resolv.conf on many systems and would undo
    a plain write, so it is told as well.
    """
    servers = [s.strip() for s in nameservers.split(",") if s.strip()]
    if not servers:
        return
    if os.path.exists("/run/systemd/resolve/stub-resolv.conf"):
        # resolved is in charge, tell it which resolvers to use
        for server in servers:
            _run("resolvectl dns %s %s" % (_primary_device(), server), check=False)
        _run("resolvectl domain %s '~.'" % _primary_device(), check=False)
        return
    content = "# written by the traffic-inspector client\n"
    for server in servers:
        content += "nameserver %s\n" % server
    with open("/etc/resolv.conf", "w", encoding="utf-8") as handle:
        handle.write(content)


def teardown(name="ti0"):
    """Remove the interface and the routes."""
    _run("ip route del 0.0.0.0/1 dev %s" % name, check=False)
    _run("ip route del 128.0.0.0/1 dev %s" % name, check=False)
    _run("ip link delete %s" % name, check=False)
