import sys
from pathlib import Path
from pydantic import ValidationError

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.web_traffic import (
    WebProtocolEnum, HttpMethodEnum, WebTrafficProfile, HttpTransactionEvent
)
from services.digital_twin.simulation.generators.web_traffic_generator import web_orchestrator

def run_web_traffic_suite():
    print("=" * 80)
    print("       WEEK 8 - DAY 53: HTTP & HTTPS WEB TRAFFIC SIMULATION AUDIT")
    print("=" * 80 + "\n")

    web_orchestrator.clear()

    # 1. Plaintext HTTP Simulation (Port 80)
    print("[1/5] Testing Plaintext HTTP Event Generation (Client -> Web:80)...")
    http_evt = web_orchestrator.http_gen.generateTransaction(
        source_dev="client-01",
        dest_dev="web-01",
        method=HttpMethodEnum.GET,
        path="/",
        status_code=200,
        req_bytes=350,
        resp_bytes=1500
    )
    print(f"    HTTP Event: {http_evt.method.value} {http_evt.path} -> Status: {http_evt.statusCode} ({http_evt.protocol.value}:{http_evt.destinationPort})")
    assert http_evt.protocol == WebProtocolEnum.HTTP
    assert http_evt.destinationPort == 80
    assert http_evt.method == HttpMethodEnum.GET
    assert http_evt.path == "/"
    assert http_evt.statusCode == 200
    assert http_evt.isEncrypted is False
    assert http_evt.requestBytes == 350
    assert http_evt.responseBytes == 1500
    print("    [PASS] Plaintext HTTP event verified.")

    # 2. Encrypted HTTPS Simulation (Port 443)
    print("\n[2/5] Testing Encrypted HTTPS Event Generation (Client -> Web:443)...")
    https_evt = web_orchestrator.https_gen.generateTransaction(
        source_dev="client-01",
        dest_dev="web-01",
        method=HttpMethodEnum.GET,
        path="/products",
        status_code=200,
        req_bytes=450,
        resp_bytes=3200
    )
    print(f"    HTTPS Event: {https_evt.method.value} {https_evt.path} -> Status: {https_evt.statusCode} ({https_evt.protocol.value}:{https_evt.destinationPort}) [Encrypted: {https_evt.isEncrypted}, TLS: {https_evt.tlsVersion}]")
    assert https_evt.protocol == WebProtocolEnum.HTTPS
    assert https_evt.destinationPort == 443
    assert https_evt.application == "WEB"
    assert https_evt.direction == "OUTBOUND"
    assert https_evt.isEncrypted is True
    assert https_evt.tlsVersion == "TLSv1.3"
    assert https_evt.requestBytes == 450 + 29  # Includes TLS record framing
    print("    [PASS] Encrypted HTTPS event verified.")

    # 3. Normal Browsing Flow (GET / -> GET /products)
    print("\n[3/5] Testing Normal User Browsing Pattern: GET / -> GET /products...")
    step1 = web_orchestrator.http_gen.generateTransaction("client-01", "web-01", method=HttpMethodEnum.GET, path="/", status_code=200)
    step2 = web_orchestrator.http_gen.generateTransaction("client-01", "web-01", method=HttpMethodEnum.GET, path="/products", status_code=200)

    print(f"    Step 1: {step1.method.value} {step1.path} -> {step1.statusCode} OK")
    print(f"    Step 2: {step2.method.value} {step2.path} -> {step2.statusCode} OK")
    assert step1.path == "/"
    assert step2.path == "/products"
    assert step1.statusCode == 200 and step2.statusCode == 200
    print("    [PASS] Browsing journey verified.")

    # 4. WebTrafficProfile Orchestration
    print("\n[4/5] Testing WebTrafficProfile Multi-Path Execution...")
    profile = WebTrafficProfile(
        name="Office-Intranet",
        protocol=WebProtocolEnum.HTTPS,
        destinationPort=443,
        requestRate=5.0,
        paths=["/", "/products", "/about", "/login"],
        statusDistribution={200: 0.80, 404: 0.20}
    )
    profile_events = web_orchestrator.generateFromProfile(profile, source_dev="client-01")
    print(f"    Profile Generated Events: {len(profile_events)}")
    for e in profile_events:
        print(f"      - [{e.protocol.value}] {e.method.value} {e.path:12s} -> HTTP {e.statusCode} | Req: {e.requestBytes}B, Resp: {e.responseBytes}B")

    assert len(profile_events) == 4
    assert profile_events[-1].method == HttpMethodEnum.POST  # /login maps to POST
    assert all(e.protocol == WebProtocolEnum.HTTPS for e in profile_events)
    print("    [PASS] Profile executed and adhered to path/method mappings.")

    # 5. Boundary Invariant & Rejection Tests
    print("\n[5/5] Executing Invariant & Rejection Tests...")

    # Port auto-normalization test
    p_norm_http = WebTrafficProfile(protocol=WebProtocolEnum.HTTP, destinationPort=443)
    assert p_norm_http.destinationPort == 80
    p_norm_https = WebTrafficProfile(protocol=WebProtocolEnum.HTTPS, destinationPort=80)
    assert p_norm_https.destinationPort == 443
    print("    [PASS] Verified automatic port normalization (HTTP->80, HTTPS->443).")

    # Negative duration
    try:
        WebTrafficProfile(duration=-10)
        assert False
    except ValidationError:
        print("    [PASS] Rejected negative profile duration.")

    # Out-of-bounds request rate (> 500 req/s)
    try:
        WebTrafficProfile(requestRate=1000.0)
        assert False
    except ValidationError:
        print("    [PASS] Rejected excessive request rate (>500 req/s).")

    print("\n" + "=" * 80)
    print("       ALL DAY 53 WEB TRAFFIC SIMULATION TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_web_traffic_suite()