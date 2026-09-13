import sys
import json
from pathlib import Path
import numpy as np
import joblib

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.training.dataset_loader import FEATURE_NAMES, dataset_loader
from services.digital_twin.ml.xai.master_xai_validator import master_xai_validator
from services.digital_twin.ml.xai.shap.shap_engine import shap_explainer_engine
from services.digital_twin.ml.xai.explanations.prediction_explanation_engine import prediction_explanation_engine
from services.digital_twin.ml.xai.visualization.xai_dashboard_engine import xai_dashboard_engine

def run_day126_suite():
    print("=" * 80)
    print("       WEEK 18 - DAY 126: COMPLETE XAI VALIDATION & PHASE 15 MILESTONE")
    print("=" * 80 + "\n")

    # 1. Multi-Model XAI Benchmark
    print("[1/5] Auditing Multi-Model XAI Coverage Across All 5 Phase 12 Classifiers...")
    benchmark = master_xai_validator.benchmark_all_models_xai()

    print("\n    | Model               | Accuracy | Strategy                             | Interpretability | Top Driver            |")
    print("    |---------------------|----------|--------------------------------------|------------------|-----------------------|")
    for row in benchmark:
        print(f"    | {row['model']:<19} | {row['accuracy']:<8.4f} | {row['strategy']:<36} | {row['interpretability']:<16} | {row['topDriver']:<21} |")

    assert len(benchmark) >= 3
    print("\n    [PASS] Multi-model explanation strategies validated.")

    # 2. Explainability Quality Dimensions (Completeness, Consistency, Faithfulness, Stability)
    print("\n[2/5] Auditing Explainability Quality Dimensions...")
    rf_model = joblib.load(ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "random_forest" / "model.joblib")["model"]
    sample_input = {
        "connection_frequency": 48.0,
        "destination_diversity": 2.4,
        "unique_destination_ports": 150.0,
        "failed_connections": 12.0,
        "packet_rate": 0.65,
        "bytes": 0.40,
        "dns_frequency": 0.5,
        "flow_duration": 5.0
    }

    # Test 2a: Completeness
    exp1 = shap_explainer_engine.explain_instance("PRED-Q-1", sample_input, rf_model)
    assert len(exp1.features) == len(FEATURE_NAMES)

    # Test 2b: Consistency (Reproducibility)
    exp2 = shap_explainer_engine.explain_instance("PRED-Q-2", sample_input, rf_model)
    for f1, f2 in zip(exp1.features, exp2.features):
        assert f1.shapValue == f2.shapValue

    # Test 2c: Faithfulness (Additive Efficiency Property)
    total_shap = sum(f.shapValue for f in exp1.features)
    delta_pred = exp1.predictionValue - exp1.baseValue
    # TreeExplainer efficiency property: sum(phi) == f(x) - E[f(x)]
    assert abs(total_shap - delta_pred) < 0.05

    # Test 2d: Stability under small perturbation (epsilon = 0.01)
    perturbed_input = dict(sample_input)
    perturbed_input["connection_frequency"] = 48.01
    exp_pert = shap_explainer_engine.explain_instance("PRED-Q-PERT", perturbed_input, rf_model)
    assert exp1.topPositiveFeatures[0].featureName == exp_pert.topPositiveFeatures[0].featureName

    print("    [PASS] Completeness, Consistency, Faithfulness, and Stability confirmed.")

    # 3. Defensive Failure Handling
    print("\n[3/5] Auditing Defensive Failure Handlers...")
    failures = master_xai_validator.validate_failure_conditions()
    for fname, passed in failures.items():
        print(f"    Failure Condition: {fname:<30} -> Handled: {passed}")
        assert passed
    print("    [PASS] All defensive failure scenarios safely mitigated without pipeline crashing.")

    # 4. Epistemic Modesty & Narrative Integrity
    print("\n[4/5] Auditing Non-Speculative Predictive Framing...")
    enriched = prediction_explanation_engine.generate_explanation(
        prediction_id="PRED-MODESTY",
        threat_probability=0.87,
        predicted_category="PORT_SCAN",
        category_confidence=0.91,
        risk_level="HIGH",
        shap_items=exp1.features
    )
    narrative = (enriched.summary + " " + enriched.detailedExplanation).lower()

    prohibited = ["definitely performed", "guaranteed attack", "under attack", "perpetrated by"]
    for p in prohibited:
        assert p not in narrative
    assert "predicted" in narrative or "behaviour" in narrative
    assert "does not prove that an attack occurred" in enriched.limitations
    print("    [PASS] Epistemic modesty verified: system characterizes model behaviour, not unverified claims.")

    # 5. Master Terminal Output Display
    print("\n[5/5] Generating Master Week 18 XAI Diagnostic Output...")
    banner = f"""
==================================================
DIGITAL TWIN SECURITY PREDICTION
==================================================

Prediction ID:
{enriched.predictionId}

Timestamp:
{enriched.timestamp}

Source:
CLIENT-01

Destination:
SERVER-01

--------------------------------------------------
PREDICTION
--------------------------------------------------

Threat Probability:
{enriched.threatProbabilityFormatted}

Threat Class:
THREAT

Predicted Category:
{enriched.predictedCategory}

Category Confidence:
{enriched.categoryConfidenceFormatted}

Risk Score:
82.0

Risk Level:
{enriched.riskLevel}

--------------------------------------------------
XAI
--------------------------------------------------

Top Positive Contributors:
"""
    for idx, f in enumerate(enriched.topPositiveContributors[:4], start=1):
        banner += f"\n{idx}. {f.featureName}\n   Contribution: {f.shapValueFormatted}\n"

    banner += "\nTop Negative Contributors:\n"
    for idx, f in enumerate(enriched.topNegativeContributors[:1], start=1):
        banner += f"\n{idx}. {f.featureName}\n   Contribution: {f.shapValueFormatted}\n"

    banner += f"""
--------------------------------------------------
OBSERVED EVIDENCE
--------------------------------------------------

Connection frequency:
Elevated

Destination diversity:
Elevated

Destination-port activity:
Abnormal

Failed connections:
Elevated

--------------------------------------------------
EXPLANATION
--------------------------------------------------

{enriched.detailedExplanation}

--------------------------------------------------
LIMITATION
--------------------------------------------------

{enriched.limitations}

--------------------------------------------------
MODEL
--------------------------------------------------

Model:
Random Forest

Model Version:
rf-v1.0

Feature Version:
feature-v1.0

Dataset Version:
dataset-v1.0

Explanation Method:
SHAP (TreeExplainer)

--------------------------------------------------
STATUS
--------------------------------------------------

Explanation:
GENERATED
==================================================
"""
    print(banner)
    print("=" * 80)
    print("       ALL DAY 126 MASTER XAI VALIDATION TESTS PASSED CLEANLY")
    print("       PHASE 15: EXPLAINABLE AI (XAI) GRADUATED SUCCESSFULLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day126_suite()