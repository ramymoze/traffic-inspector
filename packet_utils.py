import socket

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from crypto import encrypt


def Unwraping(raw_payload):
    packet = IP(raw_payload)
    payload = bytes(packet.payload.payload)
    if packet.haslayer("TCP"):
        destination_ip = packet.dst
        destination_port = packet.getlayer("TCP").dport
        protocole = "TCP"
        return (destination_ip, destination_port), protocole, payload
    elif packet.haslayer("UDP"):
        destination_ip = packet.dst
        destination_port = packet.getlayer("UDP").dport
        protocole = "UDP"
        return (destination_ip, destination_port), protocole, payload
    return (None, None), "unknown", payload


def Getservice(port, protocole):
    try:
        return socket.getservbyport(port, protocole.lower())
    except (OSError, socket.error):
        return f"Unknown ({port})"


def Sendpacket(sip, sporte, dip, dport, protocole, payload):
    payload = payload.encode()
    if protocole == "TCP":
        pkt = bytes(IP(dst=str(dip)) / TCP(dport=dport) / Raw(load=payload))
        pkt = encrypt(pkt)
        with socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM) as s:
            s.sendto(pkt, (sip, sporte))
    elif protocole == "UDP":
        pkt = bytes(IP(dst=str(dip)) / UDP(dport=dport) / Raw(load=payload))
        pkt = encrypt(pkt)
        with socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM) as s:
            s.sendto(pkt, (sip, sporte))


def HandleConnections(s, d, payload, sessions, pending_data):
    if s not in sessions:
        new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        new_socket.setblocking(False)
        new_socket.connect_ex(d)
        sessions[s] = new_socket
        pending_data[new_socket] = payload
    connection = sessions[s]
    try:
        connection.sendall(payload)
        print(f"[+] Payload sent to {d}")
    except BlockingIOError:
        pass
    except OSError as e:
        if e.winerror == 10057:
            print(f"[*] Handshake with {d} in progress... waiting.")
            pending_data[connection] = payload
        else:
            print(f"[-] Connection failed: {e}")
            connection.close()
            if s in sessions:
                del sessions[s]
    return sessions
