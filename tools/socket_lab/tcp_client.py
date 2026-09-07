import socket
import sys

def run_tcp_client(host: str = "127.0.0.1", port: int = 9001):
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[*] [TCP CLIENT] Initiating 3-Way Handshake to {host}:{port}...")
    
    client_sock.connect((host, port))
    local_ip, local_port = client_sock.getsockname()
    print(f"[+] [CONNECTED] Bound locally to ephemeral port {local_ip}:{local_port}")

    payload = b"TWIN_STATE_TELEMETRY_PROBE_01"
    print(f"    [SEND] Transmitting {len(payload)} bytes: {payload.decode()}")
    client_sock.sendall(payload)

    response = client_sock.recv(1024)
    print(f"    [RECEIVE] Received server response: {response.decode()}")

    client_sock.close()
    print("[*] [TCP TEARDOWN] Client socket closed.")

if __name__ == "__main__":
    run_tcp_client()