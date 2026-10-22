"""Client package for the traffic-inspector tunnel.

It holds the clients and the parts they share:

* ``client.tunnel``   - the handshake, the flow bookkeeping and the frame codec
* ``client.bridge``   - the TCP state machine that speaks for the kernel
* ``client.ipstack``  - a small IPv4 / TCP / UDP codec
* ``client.main``     - the command line client, it puts the whole traffic of
  the machine into the tunnel
* ``client.tun_linux``   - the TUN device of Linux
* ``client.tun_windows`` - the Wintun adapter of Windows
* ``client.socks``    - a SOCKS5 proxy, for a browser
* ``client.android``  - the application for a phone: React Native in front,
  Kotlin behind
"""
