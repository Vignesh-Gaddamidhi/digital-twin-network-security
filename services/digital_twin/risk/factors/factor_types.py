from enum import Enum
from typing import Dict, Any

class AssetCriticalityLevel(str, Enum):
    VERY_LOW = "VERY_LOW"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class VulnerabilitySeverityLevel(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AttackImpactLevel(str, Enum):
    VERY_LOW = "VERY_LOW"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class RiskLevelTier(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class RiskAssessmentStatus(str, Enum):
    CALCULATED = "CALCULATED"
    RECALCULATED = "RECALCULATED"
    INVALID = "INVALID"
    FAILED = "FAILED"

# Standard continuous scale [0.20 -> 1.00]
FACTOR_NORMALIZATION_MAP: Dict[str, float] = {
    "NONE": 0.20,
    "VERY_LOW": 0.20,
    "LOW": 0.40,
    "MEDIUM": 0.60,
    "HIGH": 0.80,
    "CRITICAL": 1.00
}

# Standard Attack Category Impact Default Policy
DEFAULT_CATEGORY_IMPACT_MAP: Dict[str, AttackImpactLevel] = {
    "NORMAL": AttackImpactLevel.VERY_LOW,
    "PORT_SCAN": AttackImpactLevel.LOW,
    "BEACONING": AttackImpactLevel.MEDIUM,
    "DNS_ANOMALY": AttackImpactLevel.MEDIUM,
    "BRUTE_FORCE_LIKE": AttackImpactLevel.HIGH,
    "DOS_LIKE": AttackImpactLevel.HIGH,
    "LATERAL_MOVEMENT_LIKE": AttackImpactLevel.HIGH,
    "EXFILTRATION_LIKE": AttackImpactLevel.CRITICAL
}