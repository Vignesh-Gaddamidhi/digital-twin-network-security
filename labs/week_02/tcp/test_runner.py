import sys
from pathlib import Path
import threading
import time
import socket

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from labs.week_02.tcp.server import run_tcp_server
from labs.week_02.tcp.client import run_tcp_client

def run_suite():
    print("================================================================================")
    print("           WEEK 2 - DAY 8: TCP CLIENT/SERVER & DIAGNOSTICS SUITE                ")
    print("================================================================================\n")

    # 1. Negative Test: Test connection refusal
    print("[+] TEST 1: Diagnostic Exception Trapping (Port 59999 Closed)")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect(("127.0.0.1", 59999))
    except (ConnectionRefusedError, socket.timeout) as e:
        print(f"    [PASS] Trapped expected kernel rejection: {type(e).__name__} ({e})\n")
    finally:
        s.close()

    # 2. Positive Test: Concurrent Client-Server Session
    print("[+] TEST 2: Active Connection Lifecycle (Port 5000)")
    server_thread = threading.Thread(target=run_tcp_server, kwargs={"port": 5000, "max_requests": 1}, daemon=True)
    server_thread.start()
    time.sleep(0.5) # Allow bind() and listen()

    run_tcp_client(port=5000, message="Hello Server - Digital Twin Session Sync")
    server_thread.join(timeout=3)
    print("\n[+] Verification suite completed cleanly.")

if __name__ == "__main__":
    run_suite()