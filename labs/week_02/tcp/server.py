import socket
import sys
from datetime import datetime

def run_tcp_server(host: str = "127.0.0.1", port: int = 5000, max_requests: int = 1):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Allow instant socket rebinding across fast test runs
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [SERVER-START] TCP Master Socket listening on {host}:{port}")

    handled = 0
    try:
        while handled < max_requests:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] [SERVER-AWAIT] Blocking on accept() waiting for 3-Way Handshake...")
            conn, client_address = server_socket.accept()
            print(f"[{datetime.now().strftime('%H:%M:%S')}] [SERVER-ACCEPT] Established connection from {client_address[0]}:{client_address[1]}")

            try:
                data = conn.recv(4096)
                if data:
                    decoded = data.decode("utf-8", errors="replace")
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] [SERVER-RECV] Inbound {len(data)} bytes: '{decoded}'")
                    
                    response = f"ACK_FROM_SERVER: Received '{decoded}' at {datetime.now().isoformat()}".encode("utf-8")
                    conn.sendall(response)
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] [SERVER-SEND] Transmitted {len(response)} bytes acknowledgment.")
            finally:
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [SERVER-CLOSE] Disconnected client {client_address[0]}:{client_address[1]}")
                handled += 1
    finally:
        server_socket.close()
        print(f"[{datetime.now().strftime('%H:%M:%S')}] [SERVER-SHUTDOWN] Master TCP socket released.")

if __name__ == "__main__":
    run_tcp_server()