import socket

def run_udp_server(host: str = "127.0.0.1", port: int = 9002):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind((host, port))
    print(f"[*] [UDP SERVER] Bound to datagram port {host}:{port} (Stateless listener)...")

    data, addr = server_sock.recvfrom(1024)
    print(f"[+] [DATAGRAM RECEIVED] Inbound from {addr[0]}:{addr[1]}")
    print(f"    Payload ({len(data)} bytes): {data.decode('utf-8', errors='replace')}")

    reply = b"UDP_DATAGRAM_ACK"
    server_sock.sendto(reply, addr)
    print(f"    [DATAGRAM SENT] Dispatched reply to {addr[0]}:{addr[1]}")
    server_sock.close()

if __name__ == "__main__":
    run_udp_server()