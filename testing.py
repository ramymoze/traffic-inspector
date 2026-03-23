from packet_utils import Sendpacket


def sendToserver(sip, sport):
    Sendpacket(
        sip,
        sport,
        "142.250.200.164",
        80,
        "TCP",
        "HEAD / HTTP/1.1\r\nHost: www.google.com\r\n\r\n",
    )


sendToserver("127.0.0.1", 5555)
