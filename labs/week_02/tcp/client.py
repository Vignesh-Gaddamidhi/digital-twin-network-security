import socket
import sys
from datetime import datetime

def run_tcp_client(host: str = "127.0.0.1", port: int = 5000, message: str = "Hello Server from D001"):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [CLIENT-INIT] Socket created. Initiating connect() to {host}:{port}...")
    try:
        client_socket.connect((host, port))
        local_ip, local_port = client_socket.getsockname()
        print(f"[{datetime.now().strftime('%H:%M:%S')}] [CLIENT-CONNECTED] Handshake complete. Local Ephemeral Port: {local_ip}:{local_port}")

        payload = message.encode("utf-8")
        print(f"[{datetime.now().strftime('%H:%M:%S')}] [CLIENT-SEND] Dispatched: '{message}' ({len(payload)} bytes)")
        client_socket.sendall(payload)

        data = client_socket.recv(4096)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] [CLIENT-RECV] Server Response: '{data.decode('utf-8', errors='replace')}'")
    except ConnectionRefusedError:
        print(f"[-] [ERROR] Connection refused. Verify server is listening on {host}:{port}")
    finally:
        client_socket.close()
        print(f"[{datetime.now().strftime('%H:%M:%S')}] [CLIENT-CLOSE] Socket closed gracefully.")

if __name__ == "__main__":
    msg = sys.argv[1] if len(sys.argv) > 1 else "Hello Server"
    run_tcp_client(message=msg)