from typing import Optional, Dict, Any, List
from packages.shared_types.src.security import AttackMapping
from packages.shared_types.src.events import SecurityEvent

class MitreAttackMapper:
    """Translates normalized SecurityEvents into standardized MITRE ATT&CK technique records."""

    @staticmethod
    def map_event_to_attack(event: SecurityEvent, context: Optional[Dict[str, Any]] = None) -> Optional[AttackMapping]:
        evt_type = event.event_type.upper()
        details = event.details or {}
        context = context or {}

        # 1. Reconnaissance / Active Scanning (T1595)
        if "SCAN" in evt_type or "PROBE" in evt_type:
            confidence = 0.85
            evidence = f"Inbound probe targeting port {event.destination_port}/{event.protocol} from {event.source_ip}"
            if context.get("ports_hit_count", 1) >= 3:
                confidence = 0.95
                evidence += f" (Multi-port sweep: {context.get('ports_hit_count')} ports hit)"

            return AttackMapping(
                tactic_id="TA0043",
                tactic_name="Reconnaissance",
                technique_id="T1595.001",
                technique_name="Active Scanning: Port Scans",
                confidence=confidence,
                evidence=evidence,
                mitre_url="https://attack.mitre.org/techniques/T1595/001/"
            )

        # 2. Execution / Command and Scripting Interpreter (T1059.004)
        if "SHELL" in evt_type or "COMMAND" in evt_type or "EXPLOIT" in evt_type:
            cve = details.get("cve", "CVE-2023-38408")
            return AttackMapping(
                tactic_id="TA0002",
                tactic_name="Execution",
                technique_id="T1059.004",
                technique_name="Command and Scripting Interpreter: Unix Shell",
                confidence=0.98,
                evidence=f"Shell payload / command injection detected over port {event.destination_port} targeting {cve}",
                mitre_url="https://attack.mitre.org/techniques/T1059/004/"
            )

        # 3. Credential Access / Password Guessing (T1110)
        if "AUTH" in evt_type or "BRUTE" in evt_type or "LOGIN" in evt_type:
            attempts = context.get("failed_attempts", 1)
            confidence = min(0.95, 0.60 + (attempts * 0.05))
            return AttackMapping(
                tactic_id="TA0006",
                tactic_name="Credential Access",
                technique_id="T1110.001",
                technique_name="Brute Force: Password Guessing",
                confidence=confidence,
                evidence=f"Repeated authentication rejections ({attempts} failures) against service port {event.destination_port}",
                mitre_url="https://attack.mitre.org/techniques/T1110/001/"
            )

        # 4. Discovery / Network Service Discovery (T1046)
        if "DISCOVERY" in evt_type or (event.source_ip.startswith("192.168.") and event.destination_ip.startswith("192.168.") and "SCAN" in evt_type):
            return AttackMapping(
                tactic_id="TA0007",
                tactic_name="Discovery",
                technique_id="T1046",
                technique_name="Network Service Discovery",
                confidence=0.90,
                evidence=f"Internal host {event.source_ip} enumerating services across LAN target {event.destination_ip}:{event.destination_port}",
                mitre_url="https://attack.mitre.org/techniques/T1046/"
            )

        # 5. Lateral Movement / Remote Services (T1021)
        if "LATERAL" in evt_type or (context.get("source_node_state") == "COMPROMISED" and event.destination_port in (22, 445, 3389)):
            return AttackMapping(
                tactic_id="TA0008",
                tactic_name="Lateral Movement",
                technique_id="T1021.004",
                technique_name="Remote Services: SSH",
                confidence=0.92,
                evidence=f"Outbound connection attempt to port {event.destination_port} originating from compromised host {event.source_ip}",
                mitre_url="https://attack.mitre.org/techniques/T1021/004/"
            )

        return None

mitre_mapper = MitreAttackMapper()