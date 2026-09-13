import json
from pathlib import Path
from typing import Dict, Any, List, Tuple
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import brier_score_loss
import joblib

ROOT_DIR = Path(__file__).resolve().parents[5]
CALIBRATION_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "calibration"

class ProbabilityCalibrationEngine:
    """Manages empirical probability calibration (Platt Scaling / Isotonic) and reliability verification."""

    def __init__(self, artifact_dir: Path = CALIBRATION_DIR):
        self.artifact_dir = artifact_dir
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.calibrator = None
        self.calibrator_method: str = "sigmoid"
        self.last_calibration_report: Dict[str, Any] = {}

    @staticmethod
    def calculate_ece(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> float:
        bins = np.linspace(0.0, 1.0, n_bins + 1)
        ece = 0.0
        n_samples = len(y_true)

        for i in range(n_bins):
            bin_lower, bin_upper = bins[i], bins[i + 1]
            in_bin = (y_prob >= bin_lower) & (y_prob <= bin_upper) if i == n_bins - 1 else (y_prob >= bin_lower) & (y_prob < bin_upper)
            bin_count = np.sum(in_bin)

            if bin_count > 0:
                bin_acc = np.mean(y_true[in_bin])
                bin_conf = np.mean(y_prob[in_bin])
                ece += (bin_count / n_samples) * abs(bin_acc - bin_conf)

        return round(float(ece), 4)

    def fit_and_audit_calibration(
        self,
        base_estimator: Any,
        X_val: np.ndarray,
        y_val: np.ndarray,
        method: str = "sigmoid"
    ) -> Dict[str, Any]:
        self.calibrator_method = method.lower()

        # 1. Extract raw positive-class probabilities from base estimator
        if hasattr(base_estimator, "predict_proba"):
            raw_probs = base_estimator.predict_proba(X_val)
            raw_p = raw_probs[:, 1] if raw_probs.ndim == 2 and raw_probs.shape[1] > 1 else raw_probs.flatten()
        elif hasattr(base_estimator, "decision_function"):
            df = base_estimator.decision_function(X_val)
            raw_p = 1.0 / (1.0 + np.exp(-df))
        else:
            raw_p = base_estimator.predict(X_val).astype(float)

        raw_p = np.clip(raw_p, 1e-6, 1.0 - 1e-6)
        raw_brier = round(float(brier_score_loss(y_val, raw_p)), 4)
        raw_ece = self.calculate_ece(y_val, raw_p)

        # 2. Fit 1D Calibrator (Platt Scaling via LogisticRegression or Isotonic)
        if self.calibrator_method == "isotonic":
            self.calibrator = IsotonicRegression(out_of_bounds="clip")
            self.calibrator.fit(raw_p, y_val)
            cal_p = self.calibrator.predict(raw_p)
        else:
            self.calibrator = LogisticRegression(solver="lbfgs", max_iter=200)
            self.calibrator.fit(raw_p.reshape(-1, 1), y_val)
            cal_p = self.calibrator.predict_proba(raw_p.reshape(-1, 1))[:, 1]

        cal_p = np.clip(cal_p, 0.0, 1.0)
        cal_brier = round(float(brier_score_loss(y_val, cal_p)), 4)
        cal_ece = self.calculate_ece(y_val, cal_p)

        # 3. Artifact persistence
        model_path = self.artifact_dir / f"calibrator_{self.calibrator_method}.joblib"
        joblib.dump({"calibrator": self.calibrator, "method": self.calibrator_method}, model_path)

        report = {
            "method": self.calibrator_method,
            "samplesEvaluated": int(len(y_val)),
            "rawMetrics": {
                "brierScore": raw_brier,
                "expectedCalibrationError": raw_ece
            },
            "calibratedMetrics": {
                "brierScore": cal_brier,
                "expectedCalibrationError": cal_ece
            },
            "improvement": {
                "brierReduction": round(raw_brier - cal_brier, 4),
                "eceReduction": round(raw_ece - cal_ece, 4)
            },
            "isReliabilityImproved": bool(cal_brier <= raw_brier or cal_ece <= raw_ece),
            "artifactPath": str(model_path)
        }

        self.last_calibration_report = report
        with open(self.artifact_dir / "calibration_report.json", "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        return report

    def calibrate_probability(self, raw_prob: float) -> float:
        if self.calibrator is None:
            return round(max(0.0, min(1.0, raw_prob)), 4)

        arr = np.array([max(1e-6, min(1.0 - 1e-6, raw_prob))])
        if self.calibrator_method == "isotonic":
            cal_val = self.calibrator.predict(arr)[0]
        else:
            cal_val = self.calibrator.predict_proba(arr.reshape(-1, 1))[0, 1]

        return round(float(np.clip(cal_val, 0.0, 1.0)), 4)

probability_calibration_engine = ProbabilityCalibrationEngine()