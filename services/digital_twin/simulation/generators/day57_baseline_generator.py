import json
import random
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime, timezone

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.topology import NetworkConnectionModel, ConnectionTypeEnum, ProtocolEnum
from packages.shared_types.src.firewall import FirewallRuleModel, NetworkZoneTypeEnum, FirewallActionEnum
from packages.shared_types.src.web_traffic import HttpMethodEnum
from packages.shared_types.src.dns_traffic import DnsRecordTypeEnum
from packages.shared_types.src.ssh_traffic import SshAuthMethodEnum
from packages.shared_types.src.baseline_dataset import NormalTrafficSummaryModel, BaselineMetadataModel

from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.connections.network_connection_registry import connection_registry
from services.digital_twin.core.topology.graph_engine import graph_engine
from services.digital_twin.core.security.firewall_engine import firewall_engine
from services.digital_twin.core.state.network_state_engine import network_state_engine

from services.digital_twin.simulation.generators.protocol_generators import protocol_coordinator
from services.digital_twin.simulation.generators.web_traffic_generator import web_orchestrator
from services.digital_twin.simulation.generators.dns_traffic_generator import dns_orchestrator
from services.digital_twin.simulation.generators.ssh_traffic_generator import ssh_orchestrator

class Day57BaselineGenerator:
    """Generates the canonical Week 8 baseline dataset with exact topology and multi-tier flows."""

    def __init__(self, output_dir: Optional[Path] = None):
        if output_dir:
            self.output_dir = output_dir
        else:
            self.output_dir = Path(__file__).resolve().parent.parent / "datasets" / "normal"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def provision_canonical_topology(self):
        """Provisions Internet -> FW -> RTR -> SW -> Web/DNS/Client -> DB topology."""
        device_registry.clear()
        connection_registry.clear()
        graph_engine.clear()
        firewall_engine.clear()

        # 8 Canonical Devices
        inet = NetworkDeviceModel(id="inet-01", hostname="INTERNET", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.EXTERNAL)
        fw = NetworkDeviceModel(id="firewall-01", hostname="FIREWALL-01", type=DeviceTypeEnum.FIREWALL, networkZone=NetworkZoneEnum.EXTERNAL)
        rtr = NetworkDeviceModel(id="router-01", hostname="ROUTER-01", type=DeviceTypeEnum.ROUTER, networkZone=NetworkZoneEnum.INTERNAL)
        sw = NetworkDeviceModel(id="switch-01", hostname="SWITCH-01", type=DeviceTypeEnum.SWITCH, networkZone=NetworkZoneEnum.INTERNAL)
        web = NetworkDeviceModel(id="web-01", hostname="WEB-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[80, 443])
        dns = NetworkDeviceModel(id="dns-01", hostname="DNS-01", type=DeviceTypeEnum.DNS_SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[53])
        cli = NetworkDeviceModel(id="client-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
        srv = NetworkDeviceModel(id="server-01", hostname="SERVER-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.INTERNAL, ports=[22])
        db = NetworkDeviceModel(id="db-01", hostname="DB-01", type=DeviceTypeEnum.DATABASE, networkZone=NetworkZoneEnum.INTERNAL, ports=[5432])

        devices = [inet, fw, rtr, sw, web, dns, cli, srv, db]
        for d in devices:
            device_registry.createDevice(d)
            graph_engine.addNode(d)

        # Connections
        conns = [
            NetworkConnectionModel(id="c-inet-fw", sourceDevice="inet-01", destinationDevice="firewall-01"),
            NetworkConnectionModel(id="c-fw-rtr", sourceDevice="firewall-01", destinationDevice="router-01"),
            NetworkConnectionModel(id="c-rtr-sw", sourceDevice="router-01", destinationDevice="switch-01"),
            NetworkConnectionModel(id="c-sw-web", sourceDevice="switch-01", destinationDevice="web-01"),
            NetworkConnectionModel(id="c-sw-dns", sourceDevice="switch-01", destinationDevice="dns-01"),
            NetworkConnectionModel(id="c-sw-cli", sourceDevice="switch-01", destinationDevice="client-01"),
            NetworkConnectionModel(id="c-sw-srv", sourceDevice="switch-01", destinationDevice="server-01"),
            NetworkConnectionModel(id="c-web-db", sourceDevice="web-01", destinationDevice="db-01"),
        ]
        for c in conns:
            connection_registry.createConnection(c)
            graph_engine.addEdge(c, is_bidirectional=True)

        # Baseline Permissive Firewall Rules
        firewall_engine.addRule(FirewallRuleModel(id="r-allow-all", sourceZone=NetworkZoneTypeEnum.INTERNAL, destinationZone=NetworkZoneTypeEnum.DMZ, action=FirewallActionEnum.ALLOW, priority=1))

    def generate_baseline(self, duration_seconds: int = 60, seed: int = 12345) -> NormalTrafficSummaryModel:
        self.provision_canonical_topology()
        rng = random.Random(seed)

        events_log: List[Dict[str, Any]] = []

        total_packets = 0
        total_bytes = 0
        tcp_count = 0
        udp_count = 0
        icmp_count = 0
        http_count = 0
        https_count = 0
        dns_count = 0
        ssh_count = 0

        port_dist: Dict[int, int] = {}
        active_conns = 0

        # Run 60-second time ticks
        sim_time = 0.0
        while sim_time < duration_seconds:
            sim_time += 1.0

            # 1. DNS Query (Client -> DNS-01)
            q, r = dns_orchestrator.generator.generateQueryPair(
                source_dev="client-01", dns_server="dns-01", domain="web.internal.test",
                query_type=DnsRecordTypeEnum.A, simulation_id="normal-baseline-run-001"
            )
            dns_bytes = q.bytes + r.bytes
            total_bytes += dns_bytes
            total_packets += 2
            udp_count += 2
            dns_count += 2
            port_dist[53] = port_dist.get(53, 0) + 2
            events_log.append(q.model_dump())
            events_log.append(r.model_dump())

            # 2. HTTPS Web Browsing (Client -> Web-01:443)
            h_evt = web_orchestrator.https_gen.generateTransaction(
                source_dev="client-01", dest_dev="web-01", method=HttpMethodEnum.GET,
                path="/products", status_code=200, simulation_id="normal-baseline-run-001"
            )
            https_b = h_evt.requestBytes + h_evt.responseBytes
            total_bytes += https_b
            total_packets += 2
            tcp_count += 2
            https_count += 1
            port_dist[443] = port_dist.get(443, 0) + 2
            events_log.append(h_evt.model_dump())

            # 3. HTTP Intranet Request (Client -> Web-01:80)
            if rng.random() < 0.6:
                http_evt = web_orchestrator.http_gen.generateTransaction(
                    source_dev="client-01", dest_dev="web-01", method=HttpMethodEnum.GET,
                    path="/api/health", status_code=200, simulation_id="normal-baseline-run-001"
                )
                http_b = http_evt.requestBytes + http_evt.responseBytes
                total_bytes += http_b
                total_packets += 2
                tcp_count += 2
                http_count += 1
                port_dist[80] = port_dist.get(80, 0) + 2
                events_log.append(http_evt.model_dump())

            # 4. ICMP Ping Health Probe (Client -> Web-01)
            if rng.random() < 0.35:
                req, rep = protocol_coordinator.emitIcmpPing("client-01", "web-01", simulation_id="normal-baseline-run-001")
                icmp_b = req.bytes + rep.bytes
                total_bytes += icmp_b
                total_packets += 2
                icmp_count += 2
                events_log.append(req.model_dump())
                events_log.append(rep.model_dump())

            # 5. SSH Admin Session (Client -> Server-01:22)
            if rng.random() < 0.2:
                seq = ssh_orchestrator.generator.generateSessionSequence(
                    source_dev="client-01", dest_dev="server-01", destination_port=22,
                    auth_method=SshAuthMethodEnum.PUBLIC_KEY, simulation_id="normal-baseline-run-001"
                )
                ssh_b = sum(s.bytes for s in seq)
                total_bytes += ssh_b
                total_packets += len(seq)
                tcp_count += len(seq)
                ssh_count += 1
                port_dist[22] = port_dist.get(22, 0) + len(seq)
                events_log.extend([s.model_dump() for s in seq])

            # 6. Web -> DB Backend Query (Web-01 -> DB-01:5432)
            db_evts = protocol_coordinator.emitTcpFlow("web-01", "db-01", dst_port=5432, payload_bytes=420, simulation_id="normal-baseline-run-001")
            db_b = sum(d.bytes for d in db_evts)
            total_bytes += db_b
            total_packets += len(db_evts)
            tcp_count += len(db_evts)
            port_dist[5432] = port_dist.get(5432, 0) + len(db_evts)
            events_log.extend([d.model_dump() for d in db_evts])

        # Aggregate Statistics
        active_conns = 18 # Active baseline session pools
        devices_count = device_registry.count()
        avg_conns = round(active_conns / devices_count, 2)
        rate_bps = round(total_bytes / duration_seconds, 2)

        total_proto = tcp_count + udp_count + icmp_count
        proto_dist = {
            "TCP": round((tcp_count / total_proto) * 100, 2),
            "UDP": round((udp_count / total_proto) * 100, 2),
            "ICMP": round((icmp_count / total_proto) * 100, 2)
        }

        summary = NormalTrafficSummaryModel(
            totalEvents=len(events_log),
            totalPackets=total_packets,
            totalBytes=total_bytes,
            trafficRateBps=rate_bps,
            tcpCount=tcp_count,
            udpCount=udp_count,
            icmpCount=icmp_count,
            httpCount=http_count,
            httpsCount=https_count,
            dnsCount=dns_count,
            sshCount=ssh_count,
            activeConnections=active_conns,
            averageConnectionsPerDevice=avg_conns,
            portDistribution=port_dist,
            protocolDistribution=proto_dist
        )

        metadata = BaselineMetadataModel(
            datasetId="normal-baseline-run-001",
            durationSeconds=duration_seconds,
            seed=seed,
            devicesCount=devices_count
        )

        # Write datasets to disk
        self._write_dataset(events_log, summary, metadata)
        return summary

    def _write_dataset(self, events: List[Dict[str, Any]], summary: NormalTrafficSummaryModel, metadata: BaselineMetadataModel):
        target_dirs = [
            self.output_dir,
            Path(__file__).resolve().parent.parent.parent.parent.parent / "data" / "simulation" / "datasets" / "normal"
        ]

        for d in target_dirs:
            d.mkdir(parents=True, exist_ok=True)
            # 1. events.jsonl
            with open(d / "events.jsonl", "w", encoding="utf-8") as f:
                for ev in events:
                    f.write(json.dumps(ev) + "\n")
            # 2. summary.json
            with open(d / "summary.json", "w", encoding="utf-8") as f:
                json.dump(summary.model_dump(), f, indent=2)
            # 3. metadata.json
            with open(d / "metadata.json", "w", encoding="utf-8") as f:
                json.dump(metadata.model_dump(), f, indent=2)

day57_generator = Day57BaselineGenerator()