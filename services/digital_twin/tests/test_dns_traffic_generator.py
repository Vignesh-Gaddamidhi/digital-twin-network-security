import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.dns_traffic import (
    DnsRecordTypeEnum, DnsResponseCodeEnum, DnsTrafficProfile, DnsTransactionEvent
)
from services.digital_twin.simulation.generators.dns_traffic_generator import dns_orchestrator

def run_dns_traffic_suite():
    print("=" * 80)
    print("       WEEK 8 - DAY 54: DNS TRAFFIC SIMULATION & RESOLUTION AUDIT")
    print("=" * 80 + "\n")

    dns_orchestrator.clear()

    # 1. DNS Query & Response Verification (A Record)
    print("[1/5] Testing Single DNS Query/Response Transaction (Client -> DNS:53)...")
    q, r = dns_orchestrator.generator.generateQueryPair(
        source_dev="client-01",
        dns_server="dns-01",
        domain="web.internal.test",
        query_type=DnsRecordTypeEnum.A,
        simulation_id="sim-dns-01"
    )

    print(f"    Query   : {q.sourceDevice}:{q.sourcePort} -> {q.destinationDevice}:{q.destinationPort} | {q.queryType.value} {q.domain} (TxID: {q.transactionId})")
    print(f"    Response: {r.sourceDevice}:{r.sourcePort} -> {r.destinationDevice}:{r.destinationPort} | RCODE: {r.rcode.value} Answers: {r.answers} (TxID: {r.transactionId})")

    # Assertions
    assert q.protocol == "UDP" and r.protocol == "UDP"
    assert q.application == "DNS" and r.application == "DNS"
    assert q.destinationPort == 53
    assert r.sourcePort == 53
    assert r.destinationPort == q.sourcePort
    assert q.sourceDevice == "client-01" and q.destinationDevice == "dns-01"
    assert r.sourceDevice == "dns-01" and r.destinationDevice == "client-01"
    assert q.transactionId == r.transactionId
    assert q.isResponse is False and r.isResponse is True
    assert r.rcode == DnsResponseCodeEnum.NOERROR
    assert "192.168.20.10" in r.answers
    assert q.timestamp is not None and r.timestamp is not None
    print("    [PASS] DNS Query and Response matched across all network attributes.")

    # 2. Testing Query Types: AAAA, CNAME, MX, TXT
    print("\n[2/5] Testing Query Types (AAAA, CNAME, MX, TXT)...")

    # AAAA
    _, r_aaaa = dns_orchestrator.generator.generateQueryPair("client-01", "dns-01", "web.internal.test", DnsRecordTypeEnum.AAAA)
    assert "2001:db8:20::10" in r_aaaa.answers
    print(f"    [PASS] AAAA Record: web.internal.test -> {r_aaaa.answers}")

    # CNAME
    _, r_cname = dns_orchestrator.generator.generateQueryPair("client-01", "dns-01", "api.internal.test", DnsRecordTypeEnum.CNAME)
    assert "web.internal.test" in r_cname.answers
    print(f"    [PASS] CNAME Record: api.internal.test -> {r_cname.answers}")

    # MX
    _, r_mx = dns_orchestrator.generator.generateQueryPair("client-01", "dns-01", "mail.internal.test", DnsRecordTypeEnum.MX)
    assert any("mail.internal.test" in ans for ans in r_mx.answers)
    print(f"    [PASS] MX Record: mail.internal.test -> {r_mx.answers}")

    # TXT
    _, r_txt = dns_orchestrator.generator.generateQueryPair("client-01", "dns-01", "example.test", DnsRecordTypeEnum.TXT)
    assert any("v=spf1" in ans for ans in r_txt.answers)
    print(f"    [PASS] TXT Record: example.test -> {r_txt.answers}")

    # 3. Testing NXDOMAIN on Non-Existent Domain
    print("\n[3/5] Testing NXDOMAIN Response on Non-Existent Domain...")
    _, r_nx = dns_orchestrator.generator.generateQueryPair("client-01", "dns-01", "ghost-domain-does-not-exist.test", DnsRecordTypeEnum.A)
    assert r_nx.rcode == DnsResponseCodeEnum.NXDOMAIN
    assert len(r_nx.answers) == 0
    print(f"    [PASS] Ghost domain correctly returned NXDOMAIN with empty answer payload.")

    # 4. Normal Multi-Domain Traffic Profile Execution
    print("\n[4/5] Testing Normal DNS Profile (web.internal.test, db.internal.test, dns.internal.test)...")
    profile = DnsTrafficProfile(
        name="Office-Resolving",
        domains=["web.internal.test", "db.internal.test", "dns.internal.test"],
        destinationDnsServer="dns-01"
    )
    events = dns_orchestrator.generateFromProfile(profile, source_dev="client-01")
    print(f"    Total Events Emitted: {len(events)} (3 queries + 3 responses)")
    assert len(events) == 6
    for i in range(0, 6, 2):
        q_evt, r_evt = events[i], events[i+1]
        print(f"      Q: {q_evt.queryType.value} {q_evt.domain} -> R: {r_evt.rcode.value} ({r_evt.answers})")
        assert q_evt.domain == r_evt.domain
        assert q_evt.transactionId == r_evt.transactionId

    print("    [PASS] Profile transactions resolved cleanly.")

    # 5. Boundary & Contract Audit
    print("\n[5/5] Auditing Complete History Queue...")
    history = dns_orchestrator.getEvents()
    assert len(history) >= 6
    print(f"    [PASS] Verified {len(history)} persistent DNS event entries in memory.")

    print("\n" + "=" * 80)
    print("       ALL DAY 54 DNS TRAFFIC SIMULATION TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_dns_traffic_suite()