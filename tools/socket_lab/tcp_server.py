import socket
import sys

def run_tcp_server(host: str = "127.0.0.1", port: int = 9001):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Enable address reuse to avoid TIME_WAIT socket lockouts during testing
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    server_sock.bind((host, port))
    server_sock.listen(5)
    print(f"[*] [TCP SERVER] Listening on {host}:{port}...")

    try:
        while True:
            client_conn, client_addr = server_sock.accept()
            print(f"[+] [TCP HANDSHAKE COMPLETE] Connected by client at {client_addr[0]}:{client_addr[1]}")
            
            data = client_conn.recv(1024)
            if not data:
                break
            
            print(f"    [RECEIVE] Received {len(data)} bytes: {data.decode('utf-8', errors='replace')}")
            
            response = b"ACK_PROCESSED: " + data
            client_conn.sendall(response)
            print(f"    [SEND] Returned acknowledgment payload to client.")
            
            client_conn.close()
            print(f"[-] [TCP TEARDOWN] Closed connection with {client_addr[0]}:{client_addr[1]}")
            break # Exit after handling demonstration transaction
    finally:
        server_sock.close()
        print("[*] TCP Server socket bound and released.")

if __name__ == "__main__":
    run_tcp_server()