import socket

from scapy.layers.inet import IP, TCP, UDP


def Unwraping(raw_payload):
    payload = IP(raw_payload)
    if payload.haslayer("TCP"):
        destination_ip = payload.dst
        destination_port = payload.getlayer("TCP").dport
        protocole = "TCP"
        return destination_ip, destination_port, protocole
    elif payload.haslayer("UDP"):
        destination_ip = payload.dst
        destination_port = payload.getlayer("UDP").dport
        protocole = "UDP"
        return destination_ip, destination_port, protocole
    return None, None, "unknown"


def Getservice(port, protocole):
    try:
        return socket.getservbyport(port, protocole.lower())
    except (OSError, socket.error):
        return f"Unknown ({port})"


def Sendpacket(sip, sporte, dip, dport, protocole):
    if protocole == "TCP":
        pkt = bytes(IP(dst=str(dip)) / TCP(dport=dport))
        with socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM) as s:
            s.sendto(pkt, (sip, sporte))
    elif protocole == "UDP":
        pkt = bytes(IP(dst=str(dip)) / UDP(dport=dport))
        with socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM) as s:
            s.sendto(pkt, (sip, sporte))
