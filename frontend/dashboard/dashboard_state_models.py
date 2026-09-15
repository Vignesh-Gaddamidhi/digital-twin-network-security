from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class ComponentStatus(str, Enum):
    LOADING = "LOADING"
    LOADED = "LOADED"
    EMPTY = "EMPTY"
    ERROR = "ERROR"
    REFRESHING = "REFRESHING"
    UNAVAILABLE = "UNAVAILABLE"

class NavigationSection(str, Enum):
    OVERVIEW = "OVERVIEW"
    TOPOLOGY = "TOPOLOGY"
    DEVICES = "DEVICES"
    TRAFFIC = "TRAFFIC"
    THREATS = "THREATS"
    PREDICTIONS = "PREDICTIONS"
    RISK = "RISK"
    ATTACK_PATHS = "ATTACK_PATHS"
    ALERTS = "ALERTS"
    SIMULATIONS = "SIMULATIONS"
    SETTINGS = "SETTINGS"

class HeaderInfo(BaseModel):
    systemTitle: str = "Network Security Digital Twin"
    systemStatus: str = "ACTIVE"
    simulationStatus: str = "RUNNING"
    environment: str = "LAB-SIMULATION"
    lastUpdated: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    notificationsCount: int = 3
    currentAnalyst: str = "Security Analyst"

class DashboardKPISummary(BaseModel):
    totalDevices: int = 12
    quarantinedDevices: int = 0
    activeThreats: int = 5
    networkRiskScore: float = 85.36
    networkRiskLevel: str = "CRITICAL"
    activeAttackPaths: int = 3
    packetsPerSecond: float = 1240.50

class ComponentState(BaseModel):
    componentId: str
    status: ComponentStatus = ComponentStatus.LOADED
    errorMessage: Optional[str] = None
    lastRefreshedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class DashboardState(BaseModel):
    stateId: str = Field(default_factory=lambda: f"DASH-{uuid.uuid4().hex[:6].upper()}")
    header: HeaderInfo = Field(default_factory=HeaderInfo)
    activeSection: NavigationSection = NavigationSection.OVERVIEW
    kpi: DashboardKPISummary = Field(default_factory=DashboardKPISummary)
    componentStates: Dict[str, ComponentState] = Field(default_factory=dict)
    networkState: Dict[str, Any] = Field(default_factory=dict)
    devices: List[Dict[str, Any]] = Field(default_factory=list)
    traffic: Dict[str, Any] = Field(default_factory=dict)
    threats: List[Dict[str, Any]] = Field(default_factory=list)
    predictions: List[Dict[str, Any]] = Field(default_factory=list)
    risks: Dict[str, Any] = Field(default_factory=dict)
    attacks: List[Dict[str, Any]] = Field(default_factory=list)
    alerts: List[Dict[str, Any]] = Field(default_factory=list)
    simulation: Dict[str, Any] = Field(default_factory=dict)

    def set_component_status(self, component_id: str, status: ComponentStatus, error_msg: Optional[str] = None):
        self.componentStates[component_id] = ComponentState(
            componentId=component_id,
            status=status,
            errorMessage=error_msg,
            lastRefreshedAt=datetime.now(timezone.utc).isoformat()
        )