import sys
from pathlib import Path

# Ensure project root is in sys.path regardless of execution entrypoint
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import threading
import time
from tools.socket_lab.tcp_server import run_tcp_server
from tools.socket_lab.tcp_client import run_tcp_client
from tools.socket_lab.udp_server import run_udp_server
from tools.socket_lab.udp_client import run_udp_client

def test_sockets():
    print("\n================= RUNNING TCP SOCKET VERIFICATION =================")
    server_thread = threading.Thread(target=run_tcp_server, daemon=True)
    server_thread.start()
    time.sleep(0.5)  # Allow server socket to bind
    run_tcp_client()
    server_thread.join(timeout=2)

    print("\n================= RUNNING UDP SOCKET VERIFICATION =================")
    udp_server_thread = threading.Thread(target=run_udp_server, daemon=True)
    udp_server_thread.start()
    time.sleep(0.5)  # Allow UDP listener to bind
    run_udp_client()
    udp_server_thread.join(timeout=2)
    print("\n[+] All transport layer sockets executed successfully.")

if __name__ == "__main__":
    test_sockets()