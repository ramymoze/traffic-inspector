import socket

from packet_utils import Unwraping


def StartServer(server_ip="0.0.0.0", port=5555):
    buffer = 65535
    UdpserverSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    UdpserverSocket.bind((server_ip, port))
    UdpserverSocket.settimeout(1)
    try:
        print("server is up and listening at " + server_ip + ":" + str(port))
        print("Press Ctrl+C to stop the server safely.\n")
        while True:
            try:
                raw_payload, sender = UdpserverSocket.recvfrom(buffer)
                if sender:
                    print("received from " + str(sender[0]) + ":" + str(sender[1]))
                    destination_ip, destination_port, protocole = Unwraping(raw_payload)
                    print(
                        f"Tunnel: {sender[0]} -> Targeting: {destination_ip}:{destination_port} via {protocole}"
                    )
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        print("\n[!] Shutdown signal received (Ctrl+C).")

    except Exception as e:
        print(f"\nServer Error: {e}")

    finally:
        print("[*] Cleaning up resources...")
        UdpserverSocket.close()
        print("Server is Down.")


StartServer("0.0.0.0", 5555)
