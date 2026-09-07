import socket
import time
from datetime import datetime

def run_udp_client(host: str = "127.0.0.1", port: int = 6000, packet_count: int = 20, delay_sec: float = 0.05):
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_sock.settimeout(1.5) # Wait up to 1.5s for ACK per packet
    
    local_ip, local_port = "0.0.0.0", 0
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [UDP-CLIENT] Initialized datagram transmission to {host}:{port}...")

    success_acks = 0
    dropped_or_lost = 0

    for seq in range(1, packet_count + 1):
        message = f"DIGITAL_TWIN_TELEMETRY_FRAME_{seq:02d}"
        payload = message.encode("utf-8")

        start_time = time.time()
        client_sock.sendto(payload, (host, port))
        
        # Check assigned ephemeral port on first send
        if seq == 1:
            local_ip, local_port = client_sock.getsockname()
            print(f"[*] [EPHEMERAL PORT] Kernel assigned outbound socket: {local_ip}:{local_port}")

        try:
            ack_data, _ = client_sock.recvfrom(2048)
            rtt_ms = (time.time() - start_time) * 1000.0
            print(f"[{datetime.now().strftime('%H:%M:%S')}] [ACK-RECV] '{ack_data.decode()}' in {rtt_ms:.2f} ms")
            success_acks += 1
        except socket.timeout:
            print(f"[-] [PACKET LOST/UNACKED] Sequence #{seq:02d} received no ACK within timeout.")
            dropped_or_lost += 1

        time.sleep(delay_sec)

    client_sock.close()
    print(f"\n[SUMMARY] Sent: {packet_count} | Confirmed ACKs: {success_acks} | Dropped: {dropped_or_lost}")
    return {"sent": packet_count, "acked": success_acks, "lost": dropped_or_lost}

if __name__ == "__main__":
    run_udp_client()