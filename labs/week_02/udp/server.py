import socket
from datetime import datetime

def run_udp_server(host: str = "127.0.0.1", port: int = 6000, expected_packets: int = 20):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind((host, port))
    server_sock.settimeout(5.0)  # Safety timeout for test completion
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [UDP-SERVER] Bound to {host}:{port}. Awaiting datagrams...")

    received_count = 0
    received_sequence = []

    try:
        while received_count < expected_packets:
            try:
                data, addr = server_sock.recvfrom(2048)
                msg = data.decode("utf-8", errors="replace")
                received_count += 1
                received_sequence.append(msg)
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [RECV #{received_count:02d}] From {addr[0]}:{addr[1]} -> '{msg}'")

                # Send lightweight acknowledgment datagram back to sender
                ack_payload = f"ACK:{msg}".encode("utf-8")
                server_sock.sendto(ack_payload, addr)
            except socket.timeout:
                print(f"[-] [TIMEOUT] No further packets received within timeout window.")
                break
    finally:
        server_sock.close()
        print(f"[{datetime.now().strftime('%H:%M:%S')}] [UDP-SERVER] Server socket closed. Total datagrams received: {received_count}")

    return received_sequence

if __name__ == "__main__":
    run_udp_server()