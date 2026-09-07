import socket

def run_udp_client(host: str = "127.0.0.1", port: int = 9002):
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"TWIN_UDP_HEARTBEAT_BURST"

    print(f"[*] [UDP CLIENT] Transmitting stateless datagram to {host}:{port}...")
    client_sock.sendto(payload, (host, port))

    data, server = client_sock.recvfrom(1024)
    print(f"[+] [REPLY RECEIVED] Source: {server[0]}:{server[1]}")
    print(f"    Payload: {data.decode()}")
    client_sock.close()

if __name__ == "__main__":
    run_udp_client()