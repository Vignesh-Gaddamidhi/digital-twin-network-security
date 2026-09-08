import json
import random
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timezone

from packages.shared_types.src.normal_traffic import (
    NormalTrafficScenarioConfig, BaselineSummaryModel,
    OrchestratorEventEnvelope, NormalProtocolWeightEnum
)
from packages.shared_types.src.web_traffic import HttpMethodEnum
from packages.shared_types.src.dns_traffic import DnsRecordTypeEnum
from packages.shared_types.src.ssh_traffic import SshAuthMethodEnum
from packages.shared_types.src.state_integration import (
    UniversalStateEvent, StateEventSourceEnum, SupportedMetricEnum
)

from services.digital_twin.simulation.generators.protocol_generators import protocol_coordinator
from services.digital_twin.simulation.generators.web_traffic_generator import web_orchestrator
from services.digital_twin.simulation.generators.dns_traffic_generator import dns_orchestrator
from services.digital_twin.simulation.generators.ssh_traffic_generator import ssh_orchestrator
from services.digital_twin.core.state.network_state_engine import network_state_engine
from services.digital_twin.core.state.unified_state_coordinator import unified_state_coordinator

class NormalTrafficOrchestrator:
    """Orchestrates combined 7-protocol normal baseline simulations and synchronizes with Digital Twin."""

    def __init__(self, baselines_dir: Optional[str] = None):
        if baselines_dir:
            self.baselines_dir = Path(baselines_dir)
        else:
            base_root = Path(__file__).resolve().parent.parent.parent.parent.parent
            self.baselines_dir = base_root / "data" / "simulation" / "baselines"

        self.baselines_dir.mkdir(parents=True, exist_ok=True)
        self._envelopes: List[OrchestratorEventEnvelope] = []
        self._active_baseline: Optional[BaselineSummaryModel] = None

    def runScenario(
        self,
        config: NormalTrafficScenarioConfig,
        sync_to_twin: bool = True
    ) -> BaselineSummaryModel:
        """Executes a multi-protocol scheduled baseline simulation across all 7 generators."""
        self._envelopes.clear()
        rng = random.Random(config.seed)

        # Set child generators and all sub-generators with deterministic child seeds
        proto_rng = random.Random(config.seed + 1)
        protocol_coordinator._rng = proto_rng
        protocol_coordinator.tcp._rng = random.Random(config.seed + 11)
        protocol_coordinator.udp._rng = random.Random(config.seed + 12)
        protocol_coordinator.icmp._rng = random.Random(config.seed + 13)

        web_rng = random.Random(config.seed + 2)
        web_orchestrator._rng = web_rng
        web_orchestrator.http_gen._rng = random.Random(config.seed + 21)
        web_orchestrator.https_gen._rng = random.Random(config.seed + 22)

        dns_rng = random.Random(config.seed + 3)
        dns_orchestrator._rng = dns_rng
        dns_orchestrator.generator._rng = random.Random(config.seed + 31)

        ssh_rng = random.Random(config.seed + 4)
        ssh_orchestrator._rng = ssh_rng
        ssh_orchestrator.generator._rng = random.Random(config.seed + 41)

                # Auto-ensure all participating devices exist in Device Registry for twin sync
        from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
        from services.digital_twin.core.devices.network_device_registry import device_registry

        for c_id in config.clientDevices:
            if not device_registry.getDevice(c_id):
                device_registry.createDevice(NetworkDeviceModel(id=c_id, hostname=c_id.upper(), type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL))

        for w_id in config.webServers:
            if not device_registry.getDevice(w_id):
                device_registry.createDevice(NetworkDeviceModel(id=w_id, hostname=w_id.upper(), type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[80, 443]))

        for d_id in config.dnsServers:
            if not device_registry.getDevice(d_id):
                device_registry.createDevice(NetworkDeviceModel(id=d_id, hostname=d_id.upper(), type=DeviceTypeEnum.DNS_SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[53]))

        for g_id in config.genericServers:
            if not device_registry.getDevice(g_id):
                device_registry.createDevice(NetworkDeviceModel(id=g_id, hostname=g_id.upper(), type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.INTERNAL, ports=[22, 5432]))

        protocols = list(config.protocolWeights.keys())
        weights = list(config.protocolWeights.values())

        proto_counts: Dict[str, int] = {}
        port_counts: Dict[int, int] = {}
        dst_counts: Dict[str, int] = {}
        total_bytes = 0
        total_packets = 0

        sim_time = 0.0
        while sim_time < config.durationSeconds:
            sim_time += config.tickStepSeconds
            selected_proto = rng.choices(protocols, weights=weights, k=1)[0]
            client = rng.choice(config.clientDevices)

            # --- PROTOCOL DISPATCHER ---
            if selected_proto == NormalProtocolWeightEnum.DNS:
                dns_srv = rng.choice(config.dnsServers)
                domain = rng.choice(["web.internal.test", "db.internal.test", "dns.internal.test", "example.test"])
                q, r = dns_orchestrator.generator.generateQueryPair(
                    source_dev=client, dns_server=dns_srv, domain=domain,
                    query_type=DnsRecordTypeEnum.A, simulation_id=config.scenarioId
                )
                b = q.bytes + r.bytes
                total_bytes += b
                total_packets += 2
                dst_port = 53
                dst_dev = dns_srv
                summary = f"DNS A {domain} -> {r.answers}"

            elif selected_proto == NormalProtocolWeightEnum.HTTPS:
                web_srv = rng.choice(config.webServers)
                path = rng.choice(["/", "/products", "/about", "/api/v1/status"])
                h_evt = web_orchestrator.https_gen.generateTransaction(
                    source_dev=client, dest_dev=web_srv, method=HttpMethodEnum.GET,
                    path=path, status_code=200, simulation_id=config.scenarioId
                )
                b = h_evt.requestBytes + h_evt.responseBytes
                total_bytes += b
                total_packets += 2
                dst_port = 443
                dst_dev = web_srv
                summary = f"HTTPS GET {path} -> 200 OK (TLSv1.3)"

            elif selected_proto == NormalProtocolWeightEnum.HTTP:
                web_srv = rng.choice(config.webServers)
                path = rng.choice(["/", "/health", "/metrics"])
                h_evt = web_orchestrator.http_gen.generateTransaction(
                    source_dev=client, dest_dev=web_srv, method=HttpMethodEnum.GET,
                    path=path, status_code=200, simulation_id=config.scenarioId
                )
                b = h_evt.requestBytes + h_evt.responseBytes
                total_bytes += b
                total_packets += 2
                dst_port = 80
                dst_dev = web_srv
                summary = f"HTTP GET {path} -> 200 OK"

            elif selected_proto == NormalProtocolWeightEnum.SSH:
                srv = rng.choice(config.genericServers)
                admin_cli = "admin-01" if "admin-01" in config.clientDevices else client
                seq = ssh_orchestrator.generator.generateSessionSequence(
                    source_dev=admin_cli, dest_dev=srv, username="sysadmin",
                    auth_method=SshAuthMethodEnum.PUBLIC_KEY, should_fail=False,
                    simulation_id=config.scenarioId
                )
                b = sum(s.bytes for s in seq)
                total_bytes += b
                total_packets += len(seq)
                dst_port = 22
                dst_dev = srv
                summary = f"SSH Admin Session (5 states: REQUESTED->CLOSED)"

            elif selected_proto == NormalProtocolWeightEnum.ICMP:
                srv = rng.choice(config.genericServers)
                req, rep = protocol_coordinator.emitIcmpPing(client, srv, simulation_id=config.scenarioId)
                b = req.bytes + rep.bytes
                total_bytes += b
                total_packets += 2
                dst_port = 0
                dst_dev = srv
                summary = f"ICMP Echo Ping Pair (seq={req.details.get('icmp_seq')})"

            elif selected_proto == NormalProtocolWeightEnum.TCP:
                srv = rng.choice(config.webServers + config.genericServers)
                tcp_evts = protocol_coordinator.emitTcpFlow(client, srv, dst_port=443, payload_bytes=512, simulation_id=config.scenarioId)
                b = sum(t.bytes for t in tcp_evts)
                total_bytes += b
                total_packets += len(tcp_evts)
                dst_port = 443
                dst_dev = srv
                summary = f"TCP 3-Way Handshake + Flow ({len(tcp_evts)} frames)"

            else: # UDP
                srv = rng.choice(config.dnsServers + config.genericServers)
                u_evt = protocol_coordinator.emitUdpDatagram(client, srv, dst_port=53, payload_bytes=96, simulation_id=config.scenarioId)
                b = u_evt.bytes
                total_bytes += b
                total_packets += 1
                dst_port = 53
                dst_dev = srv
                summary = f"Raw UDP Datagram ({b}B)"

            # Record metrics
            p_name = selected_proto.value
            proto_counts[p_name] = proto_counts.get(p_name, 0) + 1
            if dst_port > 0:
                port_counts[dst_port] = port_counts.get(dst_port, 0) + 1
            dst_counts[dst_dev] = dst_counts.get(dst_dev, 0) + 1

            envelope = OrchestratorEventEnvelope(
                simTimeSeconds=round(sim_time, 2),
                protocol=p_name,
                sourceDevice=client,
                destinationDevice=dst_dev,
                destinationPort=dst_port if dst_port > 0 else None,
                bytes=b,
                packets=1,
                summary=summary
            )
            self._envelopes.append(envelope)

            # --- SYNCHRONIZE WITH DIGITAL TWIN ---
            if sync_to_twin:
                # Update line utilization & counters on destination device
                prev_metrics = network_state_engine.getNetworkMetrics(dst_dev)
                new_bytes_in = prev_metrics.bytesReceived + b
                new_pkts_in = prev_metrics.packetsReceived + 1
                
                # Normal baseline line saturation formula (10-45% normal range)
                norm_util = min(round(12.0 + (len(self._envelopes) % 30), 2), 65.0)

                network_state_engine.updateNetworkMetrics(
                    device_id=dst_dev,
                    network_utilisation=norm_util,
                    bytes_sent=prev_metrics.bytesSent,
                    bytes_received=new_bytes_in,
                    packets_sent=prev_metrics.packetsSent,
                    packets_received=new_pkts_in
                )

                # Feed State Coordinator as REAL_NETWORK or SIMULATION
                try:
                    unified_state_coordinator.ingestEvent(UniversalStateEvent(
                        eventId=envelope.envelopeId,
                        source=StateEventSourceEnum.REAL_NETWORK,
                        deviceId=dst_dev,
                        metric=SupportedMetricEnum.NETWORK_UTILISATION,
                        value=norm_util,
                        timestamp=datetime.now(timezone.utc).isoformat()
                    ))
                except Exception:
                    pass

        # Package Baseline Summary Dataset
        baseline = BaselineSummaryModel(
            baselineId=config.scenarioId,
            scenarioName=config.name,
            seed=config.seed,
            durationSeconds=config.durationSeconds,
            totalEventsCount=len(self._envelopes),
            totalBytesTransferred=total_bytes,
            totalPacketsTransferred=total_packets,
            protocolDistribution=proto_counts,
            portDistribution=port_counts,
            destinationDistribution=dst_counts
        )
        self._active_baseline = baseline

        # Persist baseline artifact
        out_file = self.baselines_dir / f"{config.scenarioId}.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(baseline.model_dump(), f, indent=2)

        return baseline

    def getEnvelopes(self) -> List[OrchestratorEventEnvelope]:
        return list(self._envelopes)

    def getBaseline(self, baseline_id: str) -> Optional[BaselineSummaryModel]:
        if self._active_baseline and self._active_baseline.baselineId == baseline_id:
            return self._active_baseline
        f_path = self.baselines_dir / f"{baseline_id}.json"
        if f_path.exists():
            with open(f_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return BaselineSummaryModel(**data)
        return None

normal_orchestrator = NormalTrafficOrchestrator()