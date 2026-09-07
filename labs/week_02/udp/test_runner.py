import sys
from pathlib import Path
import threading
import time

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from labs.week_02.udp.server import run_udp_server
from labs.week_02.udp.client import run_udp_client

def run_suite():
    print("================================================================================")
    print("          WEEK 2 - DAY 9: UDP SOCKET RELIABILITY & DATAGRAM LAB                 ")
    print("================================================================================\n")

    server_thread = threading.Thread(target=run_udp_server, kwargs={"port": 6000, "expected_packets": 20}, daemon=True)
    server_thread.start()
    time.sleep(0.5) # Allow socket to bind

    results = run_udp_client(port=6000, packet_count=20, delay_sec=0.02)
    server_thread.join(timeout=3)

    print(f"\n[+] Reliability Metric: {results['acked']}/{results['sent']} packets received ({(results['acked']/results['sent'])*100:.1f}%)")
    print("[+] UDP Datagram suite completed cleanly.")

if __name__ == "__main__":
    run_suite()