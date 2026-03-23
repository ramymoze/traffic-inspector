import select
import socket

from crypto import decrypt, encrypt
from packet_utils import Getservice, HandleConnections, Unwraping


def StartServer(server_ip="0.0.0.0", port=5555):
    connections = {}
    reverse_connections = {}
    pending_data = {}
    buffer = 65535
    UdpserverSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    UdpserverSocket.bind((server_ip, port))
    UdpserverSocket.setblocking(False)
    try:
        print(f"[*] Tunnel is active at {server_ip}:{port}")
        print("[*] Monitoring Tunnel and Internet sessions...\n")
        while True:
            watch_list = [UdpserverSocket] + list(connections.values())
            readable, writable, _ = select.select(
                watch_list, list(connections.values()), [], 0.1
            )
            for s in writable:
                if s in pending_data:
                    try:
                        payload = pending_data.pop(s)
                        s.sendall(payload)
                        print("[+] Handshake complete! Data sent to internet.")
                    except:
                        pass
            for s in readable:
                if s is UdpserverSocket:
                    try:
                        raw_payload, sender = UdpserverSocket.recvfrom(buffer)
                        decrypted_data = decrypt(raw_payload)
                        target, proto, payload = Unwraping(decrypted_data)
                        if target[0]:
                            connections = HandleConnections(
                                sender, target, payload, connections, pending_data
                            )
                            active_socket = connections[sender]
                            reverse_connections[active_socket] = sender
                            service = Getservice(target[1], proto)
                            print(
                                f"[TUNNEL] {sender} -> {target[0]}:{target[1]} ({proto}/{service})"
                            )
                    except Exception as e:
                        print(f"[!] Inbound Error: {e}")
                else:
                    try:
                        response = s.recv(buffer)
                        phone_addr = reverse_connections.get(s)
                        if response:
                            print(
                                f"\n[<--] RESPONSE from Internet ({len(response)} bytes)"
                            )
                            if phone_addr:
                                encrypted_response = encrypt(response)
                                UdpserverSocket.sendto(encrypted_response, phone_addr)
                        else:
                            print(f"[*] Closing session for {phone_addr}")
                            s.close()
                            if phone_addr in connections:
                                del connections[phone_addr]
                            if s in reverse_connections:
                                del reverse_connections[s]
                            if s in pending_data:
                                del pending_data[s]
                    except Exception:
                        continue
    except KeyboardInterrupt:
        print("\n[!] Shutdown signal received. Closing all sockets.")
    except Exception as e:
        print(f"\n[CRITICAL] Server Error: {e}")
    finally:
        for sock in connections.values():
            sock.close()
        UdpserverSocket.close()
        print("[*] Server is Down.")


if __name__ == "__main__":
    StartServer("0.0.0.0", 5555)
