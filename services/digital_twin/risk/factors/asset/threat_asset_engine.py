import json
import math
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

ROOT_DIR = Path(__file__).resolve().parents[5]
RISK_ARTIFACTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "risk_engine"
CONTEXT_FILE = RISK_ARTIFACTS_DIR / "asset_contexts.json"

from services.digital_twin.risk.factors.factor_types import AssetCriticalityLevel, FACTOR_NORMALIZATION_MAP
from services.digital_twin.risk.factors.asset.asset_criticality_models import (
    PredictionProvenance, AssetCriticalityConfigItem, ThreatAssetContextRecord
)

class ThreatAssetEngine:
    """Binds ML threat probabilities with Digital Twin asset criticality while maintaining lineage."""

    def __init__(self, artifacts_dir: Path = RISK_ARTIFACTS_DIR):
        self.artifacts_dir = artifacts_dir
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.asset_registry: Dict[str, Dict[str, Any]] = {}
        self.criticality_configs: Dict[AssetCriticalityLevel, AssetCriticalityConfigItem] = {}
        self.history: List[ThreatAssetContextRecord] = []
        self._init_standard_configurations()
        self._init_default_assets()

    def _init_standard_configurations(self):
        self.criticality_configs = {
            AssetCriticalityLevel.VERY_LOW: AssetCriticalityConfigItem(
                level=AssetCriticalityLevel.VERY_LOW, score=0.20, description="Test client, sandbox, or non-production node"
            ),
            AssetCriticalityLevel.LOW: AssetCriticalityConfigItem(
                level=AssetCriticalityLevel.LOW, score=0.40, description="Standard user endpoint or developer workstation"
            ),
            AssetCriticalityLevel.MEDIUM: AssetCriticalityConfigItem(
                level=AssetCriticalityLevel.MEDIUM, score=0.60, description="Internal service node or non-critical application server"
            ),
            AssetCriticalityLevel.HIGH: AssetCriticalityConfigItem(
                level=AssetCriticalityLevel.HIGH, score=0.80, description="Customer-facing application server, proxy, or web tier"
            ),
            AssetCriticalityLevel.CRITICAL: AssetCriticalityConfigItem(
                level=AssetCriticalityLevel.CRITICAL, score=1.00, description="Mission-critical database, authentication server, or core backbone router"
            ),
        }

    def _init_default_assets(self):
        self.asset_registry = {
            "CLIENT-01": {
                "deviceId": "CLIENT-01",
                "deviceType": "Test Client Workstation",
                "hostname": "client-01.corp.internal",
                "ipAddress": "192.168.10.101",
                "macAddress": "00:1A:2B:3C:4D:01",
                "assetCriticality": AssetCriticalityLevel.LOW
            },
            "DNS-SERVER-01": {
                "deviceId": "DNS-SERVER-01",
                "deviceType": "DNS Server",
                "hostname": "dns-01.infra.internal",
                "ipAddress": "192.168.1.53",
                "macAddress": "00:1A:2B:3C:4D:53",
                "assetCriticality": AssetCriticalityLevel.MEDIUM
            },
            "WEB-01": {
                "deviceId": "WEB-01",
                "deviceType": "Web Application Server",
                "hostname": "web-01.dmz.internal",
                "ipAddress": "192.168.20.80",
                "macAddress": "00:1A:2B:3C:4D:80",
                "assetCriticality": AssetCriticalityLevel.HIGH
            },
            "DB-01": {
                "deviceId": "DB-01",
                "deviceType": "Production Database Server",
                "hostname": "db-01.secure.internal",
                "ipAddress": "192.168.30.10",
                "macAddress": "00:1A:2B:3C:4D:0A",
                "assetCriticality": AssetCriticalityLevel.CRITICAL
            },
            "PROD-DB-01": {
                "deviceId": "PROD-DB-01",
                "deviceType": "Database Server",
                "hostname": "prod-db-01.secure.internal",
                "ipAddress": "192.168.30.11",
                "macAddress": "00:1A:2B:3C:4D:0B",
                "assetCriticality": AssetCriticalityLevel.CRITICAL
            },
            "CORE-ROUTER-01": {
                "deviceId": "CORE-ROUTER-01",
                "deviceType": "Core Backbone Router",
                "hostname": "gw-core.backbone.internal",
                "ipAddress": "192.168.0.1",
                "macAddress": "00:1A:2B:3C:4D:FF",
                "assetCriticality": AssetCriticalityLevel.CRITICAL
            }
        }

    def validate_threat_probability(self, probability: Any) -> float:
        if probability is None:
            raise ValueError("Threat probability cannot be null.")
        if not isinstance(probability, (int, float)):
            raise ValueError(f"Threat probability must be numeric, got {type(probability).__name__}")
        if math.isnan(probability):
            raise ValueError("Threat probability cannot be NaN.")
        if math.isinf(probability):
            raise ValueError("Threat probability cannot be Infinity.")
        prob_float = float(probability)
        if prob_float < 0.0 or prob_float > 1.0:
            raise ValueError(f"Threat probability must be within [0.0, 1.0], received: {prob_float}")
        return prob_float

    def get_asset(self, device_id: str) -> Dict[str, Any]:
        d_id = device_id.strip()
        if not d_id:
            raise KeyError("deviceId cannot be empty or null.")
        if d_id not in self.asset_registry:
            raise KeyError(f"Unknown asset: '{d_id}' not found in Digital Twin topology registry.")
        return self.asset_registry[d_id]

    def update_asset_criticality(self, device_id: str, new_criticality: AssetCriticalityLevel) -> Dict[str, Any]:
        asset = self.get_asset(device_id)
        asset["assetCriticality"] = new_criticality
        return asset

    def bind_threat_to_asset(
        self,
        device_id: str,
        threat_probability: float,
        prediction_provenance: PredictionProvenance
    ) -> ThreatAssetContextRecord:
        # 1. Validate Probability
        valid_prob = self.validate_threat_probability(threat_probability)

        # 2. Asset Lookup
        asset = self.get_asset(device_id)
        crit_level = asset["assetCriticality"]
        crit_weight = self.criticality_configs[crit_level].score

        # 3. Compute Base Interaction: P_threat * C_asset
        base_score = round(valid_prob * crit_weight, 4)

        record = ThreatAssetContextRecord(
            deviceId=asset["deviceId"],
            deviceType=asset["deviceType"],
            hostname=asset["hostname"],
            ipAddress=asset["ipAddress"],
            macAddress=asset["macAddress"],
            assetCriticality=crit_level,
            criticalityWeight=crit_weight,
            threatProbability=valid_prob,
            threatProbabilityFormatted=f"{round(valid_prob * 100, 1)}%",
            baseContextScore=base_score,
            baseContextScoreFormatted=f"{round(base_score * 100, 2)} / 100.0",
            provenance=prediction_provenance
        )

        self.history.append(record)
        self._persist_context(record)
        return record

    def _persist_context(self, record: ThreatAssetContextRecord):
        existing = []
        if CONTEXT_FILE.exists():
            try:
                with open(CONTEXT_FILE, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except Exception:
                existing = []

        existing.append(record.model_dump())
        existing = existing[-100:]
        with open(CONTEXT_FILE, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)

    def clear(self):
        self.history.clear()
        self._init_default_assets()
        if CONTEXT_FILE.exists():
            try:
                CONTEXT_FILE.unlink()
            except Exception:
                pass

threat_asset_engine = ThreatAssetEngine()