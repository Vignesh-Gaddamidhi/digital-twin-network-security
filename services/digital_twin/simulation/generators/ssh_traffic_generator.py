import random
from typing import List, Optional, Tuple, Dict
from datetime import datetime, timezone
import uuid

from packages.shared_types.src.ssh_traffic import (
    SshSessionStateEnum, SshAuthMethodEnum, SshTrafficProfile, SshTransactionEvent
)
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError

class SshTargetPortClosedError(ValueError):
    pass

class SshTrafficGenerator:
    """Generates synthetic administrative SSH session lifecycles."""

    def __init__(self, rng: Optional[random.Random] = None):
        self._rng = rng or random.Random()

    def generateSessionSequence(
        self,
        source_dev: str,
        dest_dev: str,
        username: str = "sysadmin",
        auth_method: SshAuthMethodEnum = SshAuthMethodEnum.PUBLIC_KEY,
        destination_port: int = 22,
        should_fail: bool = False,
        simulation_id: str = "sim-001"
    ) -> List[SshTransactionEvent]:
        # Validate target device
        target = device_registry.getDevice(dest_dev)
        if not target:
            raise DeviceNotFoundError(f"Target server '{dest_dev}' not found in Device Registry.")

        # Validate Port 22 is open/listening on server
        if destination_port not in target.ports and destination_port != 22:
            raise SshTargetPortClosedError(f"Port {destination_port} is not configured on destination '{dest_dev}'.")

        session_id = f"ssh-sess-{uuid.uuid4().hex[:6]}"
        src_port = self._rng.randint(49152, 65535)
        events: List[SshTransactionEvent] = []

        # 1. REQUESTED (TCP Connect + Protocol Exchange)
        now_ts = datetime.now(timezone.utc).isoformat()
        events.append(SshTransactionEvent(
            sessionId=session_id,
            simulationId=simulation_id,
            timestamp=now_ts,
            sourceDevice=source_dev,
            destinationDevice=dest_dev,
            sourcePort=src_port,
            destinationPort=destination_port,
            sessionState=SshSessionStateEnum.REQUESTED,
            username=username,
            authMethod=auth_method,
            bytes=420,
            details={"step": "KEX_INIT", "client_version": "SSH-2.0-OpenSSH_9.3"}
        ))

        # 2. AUTHENTICATING (Key / Password Challenge)
        events.append(SshTransactionEvent(
            sessionId=session_id,
            simulationId=simulation_id,
            timestamp=now_ts,
            sourceDevice=source_dev,
            destinationDevice=dest_dev,
            sourcePort=src_port,
            destinationPort=destination_port,
            sessionState=SshSessionStateEnum.AUTHENTICATING,
            username=username,
            authMethod=auth_method,
            bytes=680,
            details={"step": "USERAUTH_REQUEST"}
        ))

        # If simulated failure (e.g. bad key, rejected login)
        if should_fail:
            events.append(SshTransactionEvent(
                sessionId=session_id,
                simulationId=simulation_id,
                timestamp=now_ts,
                sourceDevice=dest_dev,
                destinationDevice=source_dev,
                sourcePort=destination_port,
                destinationPort=src_port,
                sessionState=SshSessionStateEnum.FAILED,
                username=username,
                authMethod=auth_method,
                bytes=128,
                details={"step": "AUTH_FAILED", "reason": "Permission denied (publickey)"}
            ))
            return events

        # 3. ESTABLISHED (Session Ready, Shell Spawned)
        events.append(SshTransactionEvent(
            sessionId=session_id,
            simulationId=simulation_id,
            timestamp=now_ts,
            sourceDevice=source_dev,
            destinationDevice=dest_dev,
            sourcePort=src_port,
            destinationPort=destination_port,
            sessionState=SshSessionStateEnum.ESTABLISHED,
            username=username,
            authMethod=auth_method,
            bytes=1420,
            details={"step": "PTY_ALLOC_SUCCESS"}
        ))

        # 4. IDLE / INTERACTIVE (Typing, command execution)
        events.append(SshTransactionEvent(
            sessionId=session_id,
            simulationId=simulation_id,
            timestamp=now_ts,
            sourceDevice=source_dev,
            destinationDevice=dest_dev,
            sourcePort=src_port,
            destinationPort=destination_port,
            sessionState=SshSessionStateEnum.IDLE,
            username=username,
            authMethod=auth_method,
            bytes=self._rng.randint(2500, 8000),
            details={"step": "INTERACTIVE_DATA"}
        ))

        # 5. CLOSED (User exits session)
        events.append(SshTransactionEvent(
            sessionId=session_id,
            simulationId=simulation_id,
            timestamp=now_ts,
            sourceDevice=source_dev,
            destinationDevice=dest_dev,
            sourcePort=src_port,
            destinationPort=destination_port,
            sessionState=SshSessionStateEnum.CLOSED,
            username=username,
            authMethod=auth_method,
            bytes=210,
            details={"step": "SESSION_LOGOUT"}
        ))

        return events


class SshTrafficOrchestrator:
    """Orchestrates administrative SSH workloads across servers based on SshTrafficProfile."""

    def __init__(self, seed: int = 12345):
        self._rng = random.Random(seed)
        self.generator = SshTrafficGenerator(self._rng)
        self._history: List[SshTransactionEvent] = []

    def generateFromProfile(self, profile: SshTrafficProfile, simulation_id: str = "sim-001") -> List[SshTransactionEvent]:
        events = []
        for server_id in profile.targetServers:
            should_fail = (self._rng.random() < profile.failureRate)
            seq = self.generator.generateSessionSequence(
                source_dev=profile.sourceAdmin,
                dest_dev=server_id,
                auth_method=profile.authMethod,
                should_fail=should_fail,
                simulation_id=simulation_id
            )
            events.extend(seq)
            self._history.extend(seq)
        return events

    def getEvents(self) -> List[SshTransactionEvent]:
        return list(self._history)

    def clear(self):
        self._history.clear()

ssh_orchestrator = SshTrafficOrchestrator()