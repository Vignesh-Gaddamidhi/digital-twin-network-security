import random
from typing import List, Tuple, Optional
from datetime import datetime, timezone

from packages.shared_types.src.traffic_spike import (
    TrafficSpikeProfile, SpikePhaseEnum, SpikeTickTelemetry, TrafficSpikeRunResult
)
from packages.shared_types.src.protocol_traffic import (
    TransportProtocolEnum, TrafficDirectionEnum, SimulatedTcpStateEnum, UnifiedTrafficEventModel
)
from packages.shared_types.src.state_integration import (
    UniversalStateEvent, StateEventSourceEnum, SupportedMetricEnum
)
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError
from services.digital_twin.core.state.network_state_engine import network_state_engine
from services.digital_twin.core.state.performance_state_engine import performance_state_engine
from services.digital_twin.core.state.unified_state_coordinator import unified_state_coordinator

class TrafficSpikeEngine:
    """Simulates volumetric traffic spikes through baseline, ramp-up, peak, ramp-down, and recovery."""

    def __init__(self, rng: Optional[random.Random] = None):
        self._rng = rng or random.Random(99887)

    def _auto_provision(self, src: str, dst: str, port: int):
        from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
        if not device_registry.getDevice(src):
            device_registry.createDevice(NetworkDeviceModel(id=src, hostname=src.upper(), type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL))
        if not device_registry.getDevice(dst):
            device_registry.createDevice(NetworkDeviceModel(id=dst, hostname=dst.upper(), type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[port]))

    def runSpikeScenario(
        self,
        profile: TrafficSpikeProfile,
        sync_to_twin: bool = True,
        simulation_id: str = "sim-spike-01"
    ) -> TrafficSpikeRunResult:
        self._auto_provision(profile.affectedDevice, profile.targetDevice, profile.targetPort)

        timeline: List[SpikeTickTelemetry] = []
        raw_events: List[UnifiedTrafficEventModel] = []

        total_duration = (
            profile.baselineDuration +
            profile.rampUpTime +
            profile.spikeDuration +
            profile.rampDownTime +
            profile.recoveryDuration
        )

        t_base_end = profile.baselineDuration
        t_rampup_end = t_base_end + profile.rampUpTime
        t_peak_end = t_rampup_end + profile.spikeDuration
        t_rampdown_end = t_peak_end + profile.rampDownTime

        total_events = 0
        total_bytes = 0
        max_util = 0.0
        max_conns = 0
        max_cpu = 0.0

        for sec in range(1, total_duration + 1):
            sim_time = float(sec)

            # Determine Phase & Current Rate (events/minute)
            if sim_time <= t_base_end:
                phase = SpikePhaseEnum.BASELINE
                curr_rate = profile.baselineRate
            elif sim_time <= t_rampup_end:
                phase = SpikePhaseEnum.RAMP_UP
                frac = (sim_time - t_base_end) / float(profile.rampUpTime)
                curr_rate = profile.baselineRate + frac * (profile.spikeRate - profile.baselineRate)
            elif sim_time <= t_peak_end:
                phase = SpikePhaseEnum.PEAK
                curr_rate = profile.spikeRate
            elif sim_time <= t_rampdown_end:
                phase = SpikePhaseEnum.RAMP_DOWN
                frac = (sim_time - t_peak_end) / float(profile.rampDownTime)
                curr_rate = profile.spikeRate - frac * (profile.spikeRate - profile.baselineRate)
            else:
                phase = SpikePhaseEnum.RECOVERY
                curr_rate = profile.baselineRate

            # Convert rate per min to events in this 1-second tick
            events_in_sec = max(1, int(round(curr_rate / 60.0)))
            tick_bytes = 0

            # Generate individual packet events for this second
            for _ in range(events_in_sec):
                src_port = self._rng.randint(49152, 65535)
                payload_b = self._rng.randint(1024, 1460)
                tick_bytes += payload_b

                pkt = UnifiedTrafficEventModel(
                    simulationId=simulation_id,
                    sourceDevice=profile.affectedDevice,
                    destinationDevice=profile.targetDevice,
                    protocol=TransportProtocolEnum.TCP,
                    sourcePort=src_port,
                    destinationPort=profile.targetPort,
                    bytes=payload_b,
                    packets=1,
                    direction=TrafficDirectionEnum.OUTBOUND,
                    tcpState=SimulatedTcpStateEnum.ESTABLISHED,
                    details={"phase": phase.value}
                )
                raw_events.append(pkt)

            total_events += events_in_sec
            total_bytes += tick_bytes

            # Dynamic Digital Twin Metric Modeling
            norm_ratio = (curr_rate - profile.baselineRate) / max(1.0, (profile.spikeRate - profile.baselineRate))
            norm_ratio = max(0.0, min(1.0, norm_ratio))

            sim_util = round(20.0 + norm_ratio * 75.0, 2)  # 20% baseline -> 95% at peak spike
            sim_conns = int(round(5.0 + norm_ratio * 35.0))  # 5 conns -> 40 conns
            sim_cpu = round(25.0 + norm_ratio * 60.0, 2)    # 25% CPU -> 85% CPU

            max_util = max(max_util, sim_util)
            max_conns = max(max_conns, sim_conns)
            max_cpu = max(max_cpu, sim_cpu)

            tick_telemetry = SpikeTickTelemetry(
                simTimeSeconds=sim_time,
                phase=phase,
                targetDevice=profile.targetDevice,
                currentRatePerMin=round(curr_rate, 2),
                eventsInTick=events_in_sec,
                bytesInTick=tick_bytes,
                simulatedNetworkUtilisation=sim_util,
                simulatedActiveConnections=sim_conns,
                simulatedCpuLoad=sim_cpu,
                timestamp=datetime.now(timezone.utc).isoformat()
            )
            timeline.append(tick_telemetry)

            # Sync to Twin
            if sync_to_twin:
                prev_metrics = network_state_engine.getNetworkMetrics(profile.targetDevice)
                network_state_engine.updateNetworkMetrics(
                    device_id=profile.targetDevice,
                    network_utilisation=sim_util,
                    bytes_sent=prev_metrics.bytesSent,
                    bytes_received=prev_metrics.bytesReceived + tick_bytes,
                    packets_sent=prev_metrics.packetsSent,
                    packets_received=prev_metrics.packetsReceived + events_in_sec
                )
                performance_state_engine.updateCpu(profile.targetDevice, sim_cpu, source="SIMULATION")

                try:
                    unified_state_coordinator.ingestEvent(UniversalStateEvent(
                        eventId=f"spike-util-{sec}",
                        source=StateEventSourceEnum.SIMULATION,
                        deviceId=profile.targetDevice,
                        metric=SupportedMetricEnum.NETWORK_UTILISATION,
                        value=sim_util
                    ))
                    unified_state_coordinator.ingestEvent(UniversalStateEvent(
                        eventId=f"spike-cpu-{sec}",
                        source=StateEventSourceEnum.SIMULATION,
                        deviceId=profile.targetDevice,
                        metric=SupportedMetricEnum.CPU,
                        value=sim_cpu
                    ))
                except Exception:
                    pass

        return TrafficSpikeRunResult(
            profileId=profile.profileId,
            targetDevice=profile.targetDevice,
            totalDurationSeconds=total_duration,
            totalEventsEmitted=total_events,
            totalBytesTransferred=total_bytes,
            peakRatePerMinObserved=profile.spikeRate,
            maxNetworkUtilisation=max_util,
            maxActiveConnections=max_conns,
            maxCpuLoad=max_cpu,
            telemetryTimeline=timeline
        )

traffic_spike_engine = TrafficSpikeEngine()