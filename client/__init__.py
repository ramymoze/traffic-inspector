"""Client package for the traffic-inspector tunnel.

Phase 2 of the plan adds the TUN based clients here:

* ``client/linux``  - TUN client for Linux
* ``client/windows`` - TUN client using Wintun
* ``client/android`` - Kotlin ``VpnService`` application

``client.tunnel`` already holds the shared part: the handshake, the flow
bookkeeping and the frame codec.
"""
