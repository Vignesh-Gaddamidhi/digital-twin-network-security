import enum
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime,
    ForeignKey, Text, Enum as SAEnum, BigInteger
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class UserStatusEnum(str, enum.Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    LOCKED = "LOCKED"
    SUSPENDED = "SUSPENDED"

class PortStateEnum(str, enum.Enum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    FILTERED = "FILTERED"
    UNKNOWN = "UNKNOWN"

class AlertStatusEnum(str, enum.Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    CLOSED = "CLOSED"

class IncidentStatusEnum(str, enum.Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"

class ThreatWarningStatusEnum(str, enum.Enum):
    NO_WARNING = "NO_WARNING"
    WATCH = "WATCH"
    EARLY_WARNING = "EARLY_WARNING"
    HIGH_CONFIDENCE_WARNING = "HIGH_CONFIDENCE_WARNING"
    IMPACT_STAGE = "IMPACT_STAGE"

class AttackPathStatusEnum(str, enum.Enum):
    POSSIBLE = "POSSIBLE"
    ACTIVE_SIMULATED = "ACTIVE_SIMULATED"
    BLOCKED = "BLOCKED"
    MITIGATED = "MITIGATED"
    HISTORICAL = "HISTORICAL"
    UNVERIFIED = "UNVERIFIED"

# ==================== IDENTITY ====================

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    display_name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role_id = Column(String, ForeignKey("roles.id"), nullable=False)
    status = Column(SAEnum(UserStatusEnum, name="UserStatus", native_enum=True), default=UserStatusEnum.ACTIVE, nullable=False)
    last_activity = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    role = relationship("Role", back_populates="users")
    audit_logs = relationship("AuditLog", back_populates="user")

class Role(Base):
    __tablename__ = "roles"

    id = Column(String, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    users = relationship("User", back_populates="role")
    role_permissions = relationship("RolePermission", back_populates="role", cascade="all, delete-orphan")

class Permission(Base):
    __tablename__ = "permissions"

    id = Column(String, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    role_permissions = relationship("RolePermission", back_populates="permission", cascade="all, delete-orphan")

class RolePermission(Base):
    __tablename__ = "role_permissions"

    role_id = Column(String, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)
    permission_id = Column(String, ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True)
    assigned_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    role = relationship("Role", back_populates="role_permissions")
    permission = relationship("Permission", back_populates="role_permissions")

# ==================== DIGITAL TWIN ====================

class Device(Base):
    __tablename__ = "devices"

    id = Column(String, primary_key=True)
    hostname = Column(String, nullable=False)
    device_type = Column(String, nullable=False)
    network_zone = Column(String, nullable=False)
    primary_ip = Column(String, nullable=False)
    ip_addresses = Column(ARRAY(String), default=list, nullable=False)
    mac_addresses = Column(ARRAY(String), default=list, nullable=False)
    operating_system = Column(String, nullable=True)
    role = Column(String, nullable=True)
    security_state = Column(String, default="NORMAL", nullable=False)
    operational_state = Column(String, default="HEALTHY", nullable=False)
    risk_score = Column(Float, default=0.0, nullable=False)
    is_compromised = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    interfaces = relationship("DeviceInterface", back_populates="device", cascade="all, delete-orphan")
    services = relationship("DeviceService", back_populates="device", cascade="all, delete-orphan")
    ports = relationship("DevicePort", back_populates="device", cascade="all, delete-orphan")
    routes = relationship("DeviceRoute", back_populates="device", cascade="all, delete-orphan")
    out_connections = relationship("NetworkConnection", foreign_keys="NetworkConnection.source_device_id", back_populates="source_device", cascade="all, delete-orphan")
    in_connections = relationship("NetworkConnection", foreign_keys="NetworkConnection.destination_device_id", back_populates="dest_device", cascade="all, delete-orphan")
    out_edges = relationship("TopologyEdge", foreign_keys="TopologyEdge.source_device_id", back_populates="source_device", cascade="all, delete-orphan")
    in_edges = relationship("TopologyEdge", foreign_keys="TopologyEdge.destination_device_id", back_populates="dest_device", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="affected_device", cascade="all, delete-orphan")
    predictions = relationship("Prediction", back_populates="device", cascade="all, delete-orphan")
    temporal_predictions = relationship("TemporalPrediction", back_populates="device", cascade="all, delete-orphan")
    risk_assessments = relationship("RiskAssessment", back_populates="device", cascade="all, delete-orphan")
    source_attack_paths = relationship("AttackPath", foreign_keys="AttackPath.source_device_id", back_populates="source_device", cascade="all, delete-orphan")
    dest_attack_paths = relationship("AttackPath", foreign_keys="AttackPath.destination_device_id", back_populates="dest_device", cascade="all, delete-orphan")

class DeviceInterface(Base):
    __tablename__ = "interfaces"

    id = Column(String, primary_key=True)
    device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    interface_name = Column(String, nullable=False)
    mac_address = Column(String, nullable=True)
    ip_address = Column(String, nullable=False)
    subnet = Column(String, default="255.255.255.0", nullable=True)
    gateway = Column(String, nullable=True)
    status = Column(String, default="UP", nullable=False)
    speed = Column(String, default="1Gbps", nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    device = relationship("Device", back_populates="interfaces")

class DeviceService(Base):
    __tablename__ = "services"

    id = Column(String, primary_key=True)
    device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    name = Column(String, nullable=False)
    protocol = Column(String, default="TCP", nullable=False)
    port = Column(Integer, nullable=False)
    status = Column(String, default="RUNNING", nullable=False)
    version = Column(String, default="1.0.0", nullable=True)
    security_state = Column(String, default="NORMAL", nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    device = relationship("Device", back_populates="services")

class DevicePort(Base):
    __tablename__ = "ports"

    id = Column(String, primary_key=True)
    device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    port_number = Column(Integer, nullable=False)
    protocol = Column(String, default="TCP", nullable=False)
    state = Column(SAEnum(PortStateEnum, name="PortState", native_enum=True), default=PortStateEnum.OPEN, nullable=False)
    service = Column(String, nullable=True)
    exposure = Column(String, default="INTERNAL", nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    device = relationship("Device", back_populates="ports")

class DeviceRoute(Base):
    __tablename__ = "device_routes"

    id = Column(String, primary_key=True)
    device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    destination_cidr = Column(String, nullable=False)
    gateway_ip = Column(String, nullable=False)
    interface_id = Column(String, nullable=False)
    metric = Column(Integer, default=1, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    device = relationship("Device", back_populates="routes")

class NetworkConnection(Base):
    __tablename__ = "connections"

    id = Column(String, primary_key=True)
    source_device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    destination_device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    protocol = Column(String, default="TCP", nullable=False)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    status = Column(String, default="ACTIVE", nullable=False)
    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    connection_count = Column(Integer, default=1, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    source_device = relationship("Device", foreign_keys=[source_device_id], back_populates="out_connections")
    dest_device = relationship("Device", foreign_keys=[destination_device_id], back_populates="in_connections")

class TopologyEdge(Base):
    __tablename__ = "topology_edges"

    id = Column(String, primary_key=True)
    source_device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    destination_device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    edge_type = Column(String, default="LOGICAL", nullable=False)
    protocol = Column(String, default="TCP", nullable=False)
    status = Column(String, default="ACTIVE", nullable=False)
    weight = Column(Float, default=1.0, nullable=False)
    metadata_json = Column("metadata", JSONB, default=dict, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    source_device = relationship("Device", foreign_keys=[source_device_id], back_populates="out_edges")
    dest_device = relationship("Device", foreign_keys=[destination_device_id], back_populates="in_edges")

# ==================== TELEMETRY & EVENTS ====================

class Telemetry(Base):
    __tablename__ = "telemetry"

    id = Column(String, primary_key=True)
    device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    cpu_usage = Column(Float, nullable=False)
    memory_usage = Column(Float, nullable=False)
    network_utilization = Column(Float, default=0.0, nullable=False)
    packet_rate = Column(Float, nullable=False)
    byte_rate = Column(Float, nullable=False)
    active_connections = Column(Integer, default=0, nullable=False)
    security_state = Column(String, default="NORMAL", nullable=False)
    risk_score = Column(Float, default=0.0, nullable=False)
    source = Column(String, default="TWIN_AGENT", nullable=False)

class TrafficFlow(Base):
    __tablename__ = "traffic_flows"

    id = Column(String, primary_key=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    source_device_id = Column(String, ForeignKey("devices.id", ondelete="SET NULL"), nullable=True)
    destination_device_id = Column(String, ForeignKey("devices.id", ondelete="SET NULL"), nullable=True)
    source_ip = Column(String, nullable=False)
    destination_ip = Column(String, nullable=False)
    source_port = Column(Integer, nullable=False)
    destination_port = Column(Integer, nullable=False)
    protocol = Column(String, default="TCP", nullable=False)
    packet_count = Column(Integer, nullable=False)
    byte_count = Column(BigInteger, nullable=False)
    flow_duration = Column(Float, default=0.0, nullable=False)
    connection_count = Column(Integer, default=1, nullable=False)
    status = Column(String, default="ESTABLISHED", nullable=False)

class SecurityEvent(Base):
    __tablename__ = "security_events"

    event_id = Column(String, primary_key=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    source = Column(String, nullable=False)
    destination = Column(String, nullable=False)
    device_id = Column(String, ForeignKey("devices.id", ondelete="SET NULL"), nullable=True)
    protocol = Column(String, default="TCP", nullable=False)
    port = Column(Integer, nullable=True)
    event_type = Column(String, nullable=False)
    severity = Column(String, default="INFO", nullable=False)
    detection_source = Column(String, nullable=False)
    detection_type = Column(String, nullable=False)
    confidence = Column(Float, default=1.0, nullable=False)
    evidence = Column(Text, nullable=True)
    status = Column(String, default="UNRESOLVED", nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    ids_events = relationship("IdsEvent", back_populates="security_event")

class IdsEvent(Base):
    __tablename__ = "ids_events"

    id = Column(String, primary_key=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    source = Column(String, nullable=False)
    destination = Column(String, nullable=False)
    protocol = Column(String, default="TCP", nullable=False)
    port = Column(Integer, nullable=True)
    signature = Column(String, nullable=False)
    signature_id = Column(Integer, nullable=False)
    severity = Column(String, default="HIGH", nullable=False)
    category = Column(String, default="ATTEMPTED_ADMIN", nullable=False)
    sensor = Column(String, default="SURICATA", nullable=False)
    raw_reference = Column(Text, nullable=True)
    security_event_id = Column(String, ForeignKey("security_events.event_id", ondelete="SET NULL"), nullable=True)

    security_event = relationship("SecurityEvent", back_populates="ids_events")

# ==================== SOC INTELLIGENCE ====================

class Alert(Base):
    __tablename__ = "alerts"

    alert_id = Column(String, primary_key=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    source = Column(String, nullable=False)
    destination = Column(String, nullable=False)
    protocol = Column(String, default="TCP", nullable=False)
    port = Column(Integer, nullable=True)
    event_type = Column(String, nullable=False)
    severity = Column(String, default="MEDIUM", nullable=False)
    detection_source = Column(String, nullable=False)
    detection_type = Column(String, nullable=False)
    confidence = Column(Float, default=1.0, nullable=False)
    risk_score = Column(Float, default=0.0, nullable=False)
    risk_level = Column(String, default="MEDIUM", nullable=False)
    affected_device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    status = Column(SAEnum(AlertStatusEnum, name="AlertStatus", native_enum=True), default=AlertStatusEnum.NEW, nullable=False)
    evidence = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    incident_id = Column(String, ForeignKey("incidents.incident_id", ondelete="SET NULL"), nullable=True)
    security_event_id = Column(String, ForeignKey("security_events.event_id", ondelete="SET NULL"), nullable=True)

    affected_device = relationship("Device", back_populates="alerts")
    incident = relationship("Incident", back_populates="alerts")
    predictions = relationship("Prediction", back_populates="alert")

class Incident(Base):
    __tablename__ = "incidents"

    incident_id = Column(String, primary_key=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, default="HIGH", nullable=False)
    status = Column(SAEnum(IncidentStatusEnum, name="IncidentStatus", native_enum=True), default=IncidentStatusEnum.OPEN, nullable=False)
    assigned_operator = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    alerts = relationship("Alert", back_populates="incident")
    predictions = relationship("Prediction", back_populates="incident")
    risk_assessments = relationship("RiskAssessment", back_populates="incident")
    attack_paths = relationship("AttackPath", back_populates="incident")

class Prediction(Base):
    __tablename__ = "predictions"

    prediction_id = Column(String, primary_key=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    source = Column(String, nullable=True)
    destination = Column(String, nullable=True)
    threat_probability = Column(Float, nullable=False)
    threat_class = Column(String, nullable=False)
    predicted_category = Column(String, nullable=False)
    category_confidence = Column(Float, nullable=False)
    risk_score = Column(Float, default=0.0, nullable=False)
    risk_level = Column(String, default="MEDIUM", nullable=False)
    model_name = Column(String, nullable=False)
    model_version = Column(String, nullable=False)
    feature_version = Column(String, default="v1.0", nullable=False)
    evidence = Column(Text, nullable=True)
    prediction_status = Column(String, default="ACTIVE", nullable=False)

    alert_id = Column(String, ForeignKey("alerts.alert_id", ondelete="SET NULL"), nullable=True)
    incident_id = Column(String, ForeignKey("incidents.incident_id", ondelete="SET NULL"), nullable=True)

    device = relationship("Device", back_populates="predictions")
    alert = relationship("Alert", back_populates="predictions")
    incident = relationship("Incident", back_populates="predictions")
    xai_explanation = relationship("XaiExplanation", back_populates="prediction", uselist=False, cascade="all, delete-orphan")

class TemporalPrediction(Base):
    __tablename__ = "temporal_predictions"

    prediction_id = Column(String, primary_key=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    current_threat_probability = Column(Float, nullable=False)
    future_threat_probability = Column(Float, nullable=False)
    prediction_horizon = Column(String, default="30s", nullable=False)
    lead_time = Column(Float, nullable=False)
    impact_stage = Column(String, nullable=False)
    warning_status = Column(SAEnum(ThreatWarningStatusEnum, name="ThreatWarningStatus", native_enum=True), default=ThreatWarningStatusEnum.WATCH, nullable=False)
    model_name = Column(String, nullable=False)
    model_version = Column(String, nullable=False)
    feature_version = Column(String, default="v1.0", nullable=False)

    device = relationship("Device", back_populates="temporal_predictions")

class XaiExplanation(Base):
    __tablename__ = "xai_explanations"

    explanation_id = Column(String, primary_key=True)
    prediction_id = Column(String, ForeignKey("predictions.prediction_id", ondelete="CASCADE"), unique=True, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    model_name = Column(String, nullable=False)
    model_version = Column(String, nullable=False)
    base_value = Column(Float, nullable=False)
    prediction_probability = Column(Float, nullable=False)
    feature_values = Column(JSONB, nullable=False)
    feature_importance = Column(JSONB, nullable=False)
    shap_contributions = Column(JSONB, nullable=False)
    human_explanation = Column(Text, nullable=False)
    explanation_type = Column(String, default="TreeSHAP", nullable=False)

    prediction = relationship("Prediction", back_populates="xai_explanation")

class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    risk_id = Column(String, primary_key=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    threat_probability = Column(Float, nullable=False)
    asset_criticality = Column(Float, nullable=False)
    vulnerability_factor = Column(Float, nullable=False)
    attack_impact = Column(Float, nullable=False)
    risk_score = Column(Float, nullable=False)
    risk_level = Column(String, nullable=False)
    source = Column(String, default="CANONICAL_ENGINE", nullable=False)

    incident_id = Column(String, ForeignKey("incidents.incident_id", ondelete="SET NULL"), nullable=True)

    device = relationship("Device", back_populates="risk_assessments")
    incident = relationship("Incident", back_populates="risk_assessments")

class AttackPath(Base):
    __tablename__ = "attack_paths"

    attack_path_id = Column(String, primary_key=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    source_device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    destination_device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    path = Column(ARRAY(String), default=list, nullable=False)
    risk_score = Column(Float, nullable=False)
    vulnerabilities = Column(ARRAY(String), default=list, nullable=False)
    exposure = Column(String, default="INTERNAL", nullable=False)
    reachability = Column(String, default="POSSIBLE", nullable=False)
    status = Column(SAEnum(AttackPathStatusEnum, name="AttackPathStatus", native_enum=True), default=AttackPathStatusEnum.POSSIBLE, nullable=False)
    evidence = Column(Text, nullable=True)

    incident_id = Column(String, ForeignKey("incidents.incident_id", ondelete="SET NULL"), nullable=True)

    source_device = relationship("Device", foreign_keys=[source_device_id], back_populates="source_attack_paths")
    dest_device = relationship("Device", foreign_keys=[destination_device_id], back_populates="dest_attack_paths")
    incident = relationship("Incident", back_populates="attack_paths")

# ==================== GOVERNANCE ====================

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    operator = Column(String, nullable=False)
    action = Column(String, nullable=False)
    object_type = Column(String, nullable=False)
    object_id = Column(String, nullable=False)
    previous_state = Column(String, nullable=True)
    new_state = Column(String, nullable=False)
    mode = Column(String, default="SIMULATION", nullable=False)
    result = Column(String, default="SUCCESS", nullable=False)
    reason = Column(Text, nullable=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=True)

    user = relationship("User", back_populates="audit_logs")