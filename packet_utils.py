from scapy.layers.inet import IP


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
