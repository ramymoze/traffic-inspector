import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client import tun_windows

ROUTE_TABLE = """
===========================================================================
Interface List
 12...00 00 00 00 00 00 ......Intel(R) I219-V
===========================================================================
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.10     35
        127.0.0.0        255.0.0.0         0.0.0.0       127.0.0.1    331
       192.168.1.0    255.255.255.0         0.0.0.0     192.168.1.10    281
"""


def test_the_way_out_of_the_machine_is_found():
    """The tunnel server has to stay reachable without the tunnel."""
    gateway, interface = tun_windows.parse_default_route(ROUTE_TABLE)
    assert gateway == "192.168.1.1"
    assert interface == "192.168.1.10"


def test_without_a_default_route_nothing_is_found():
    assert tun_windows.parse_default_route("") == (None, None)
    only_local = (
        "        127.0.0.0        255.0.0.0         0.0.0.0       127.0.0.1    331"
    )
    assert tun_windows.parse_default_route(only_local) == (None, None)


def test_the_netmask_of_a_prefix():
    assert tun_windows._netmask(24) == "255.255.255.0"
    assert tun_windows._netmask(8) == "255.0.0.0"
    assert tun_windows._netmask(32) == "255.255.255.255"


def test_the_driver_is_looked_for_next_to_the_client():
    """Without the driver the client has to say so, not fall over."""
    assert tun_windows.find_dll("does-not-exist.dll") is None
