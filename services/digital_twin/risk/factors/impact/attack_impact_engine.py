from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

from services.digital_twin.risk.factors.factor_types import (
    AttackImpactLevel, FACTOR_NORMALIZATION_MAP, DEFAULT_CATEGORY_IMPACT_MAP
)

class AttackImpactRecord(BaseModel):
    category: str
    impactLevel: AttackImpactLevel
    impactScore: float
    affectedAssetType: str = "Standard Endpoint"
    affectedService: str = "General"
    isEscalated: bool = False
    rationale: str
    configurationVersion: str = "v1.0"

class AttackImpactEngine:
    """Computes asset-aware attack impact scores based on category, asset type, and service."""

    CRITICAL_ASSET_TYPES = {
        "DATABASE SERVER", "PRODUCTION DATABASE SERVER", "CORE BACKBONE ROUTER",
        "DOMAIN CONTROLLER", "IDENTITY PROVIDER", "PAYMENT GATEWAY"
    }

    TIER_ORDER = [
        AttackImpactLevel.VERY_LOW,
        AttackImpactLevel.LOW,
        AttackImpactLevel.MEDIUM,
        AttackImpactLevel.HIGH,
        AttackImpactLevel.CRITICAL
    ]

    def __init__(self):
        self.category_impact_map: Dict[str, AttackImpactLevel] = dict(DEFAULT_CATEGORY_IMPACT_MAP)

    def evaluate_impact(
        self,
        category: str,
        asset_type: str = "Standard Endpoint",
        service: str = "General"
    ) -> AttackImpactRecord:
        cat_key = category.strip().upper()

        # 1. Base Impact Lookup (fallback to MEDIUM if unknown)
        if cat_key in self.category_impact_map:
            base_tier = self.category_impact_map[cat_key]
            is_unknown = False
        else:
            base_tier = AttackImpactLevel.MEDIUM
            is_unknown = True

        # 2. Asset-Aware Context Escalation
        idx = self.TIER_ORDER.index(base_tier)
        is_critical_asset = asset_type.strip().upper() in self.CRITICAL_ASSET_TYPES
        is_escalated = False

        # If targeting a critical asset and base impact is not already CRITICAL, escalate by 1 tier
        if is_critical_asset and idx < len(self.TIER_ORDER) - 1 and base_tier != AttackImpactLevel.VERY_LOW:
            final_tier = self.TIER_ORDER[idx + 1]
            is_escalated = True
            rationale = (
                f"Base impact for {cat_key} ({base_tier.value}) escalated to {final_tier.value} "
                f"because target asset type '{asset_type}' is designated as mission-critical."
            )
        elif is_unknown:
            final_tier = base_tier
            rationale = f"Unknown attack category '{category}' mapped to conservative fallback impact {final_tier.value}."
        else:
            final_tier = base_tier
            rationale = f"Standard impact mapping applied for {cat_key} on {asset_type}."

        score = FACTOR_NORMALIZATION_MAP.get(final_tier.value, 0.40)

        return AttackImpactRecord(
            category=cat_key,
            impactLevel=final_tier,
            impactScore=score,
            affectedAssetType=asset_type,
            affectedService=service,
            isEscalated=is_escalated,
            rationale=rationale
        )

attack_impact_engine = AttackImpactEngine()