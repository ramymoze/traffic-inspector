from packet_utils import Sendpacket


def sendToserver(sip, sport):
    Sendpacket(sip, sport, "8.8.8.8", 80, "TCP")


sendToserver("127.0.0.1", 5555)
