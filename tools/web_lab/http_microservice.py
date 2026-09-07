import sys
from pathlib import Path

# Ensure root path is accessible
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import json
import urllib.request
import time

class TelemetryHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            response = {"status": "HEALTHY", "node": "srv-web-01", "entropy": 3.12}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        print(f"\n[+] [HTTP MICROSERVICE] Received POST {self.path}")
        print(f"    Headers: User-Agent={self.headers.get('User-Agent')}")
        print(f"    Body: {post_data.decode('utf-8', errors='replace')}")

        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"result": "RECORD_COMMITTED"}).encode("utf-8"))

    def log_message(self, format, *args):
        # Suppress standard terminal noise
        return

def run_server(port=8080):
    server = HTTPServer(("127.0.0.1", port), TelemetryHandler)
    server.serve_forever()

def execute_http_client_flow(port=8080):
    time.sleep(0.5)
    print("\n--- INITIATING HTTP L7 CLIENT TRANSACTIONS ---")

    # 1. GET Request
    get_req = urllib.request.Request(f"http://127.0.0.1:{port}/health", headers={"User-Agent": "DigitalTwin-Agent/1.0"})
    with urllib.request.urlopen(get_req) as response:
        status = response.getcode()
        body = response.read().decode()
        print(f"[+] [GET RESPONSE] Status: {status} | Body: {body}")

    # 2. POST Request
    post_payload = json.dumps({"telemetry_event": "SCAN_DETECTED", "severity": 4}).encode("utf-8")
    post_req = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/v1/event",
        data=post_payload,
        headers={"Content-Type": "application/json", "User-Agent": "DigitalTwin-Agent/1.0"},
        method="POST"
    )
    with urllib.request.urlopen(post_req) as response:
        status = response.getcode()
        body = response.read().decode()
        print(f"[+] [POST RESPONSE] Status: {status} | Body: {body}")

def main():
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    execute_http_client_flow()
    print("\n[+] L7 HTTP verification transaction completed successfully.")

if __name__ == "__main__":
    main()