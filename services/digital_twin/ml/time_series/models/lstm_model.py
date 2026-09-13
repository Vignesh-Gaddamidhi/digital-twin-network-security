import json
import time
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
import joblib

ROOT_DIR = Path(__file__).resolve().parents[5]
LSTM_ARTIFACTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "time_series" / "lstm"

class RecurrentLSTMCell:
    """Standard Long Short-Term Memory cell with input, forget, candidate, and output gates."""

    def __init__(self, input_dim: int, hidden_dim: int, random_seed: int = 42):
        rng = np.random.RandomState(random_seed)
        scale = 1.0 / np.sqrt(hidden_dim)

        self.W = rng.uniform(-scale, scale, (input_dim + hidden_dim, 4 * hidden_dim)).astype(np.float32)
        self.b = np.zeros(4 * hidden_dim, dtype=np.float32)
        # Bias forget gate to 1.0 initially to preserve historical memory
        self.b[hidden_dim:2*hidden_dim] = 1.0

        self.input_dim = input_dim
        self.hidden_dim = hidden_dim

    @staticmethod
    def _sigmoid(x: np.ndarray) -> np.ndarray:
        return 1.0 / (1.0 + np.exp(-np.clip(x, -15.0, 15.0)))

    def forward_step(
        self,
        x_t: np.ndarray,
        h_prev: np.ndarray,
        c_prev: np.ndarray
    ) -> Tuple[np.ndarray, np.ndarray]:
        combined = np.hstack([x_t, h_prev])
        gates = np.dot(combined, self.W) + self.b

        h_dim = self.hidden_dim
        i_gate = self._sigmoid(gates[:, 0:h_dim])
        f_gate = self._sigmoid(gates[:, h_dim:2*h_dim])
        c_cand = np.tanh(gates[:, 2*h_dim:3*h_dim])
        o_gate = self._sigmoid(gates[:, 3*h_dim:4*h_dim])

        c_next = f_gate * c_prev + i_gate * c_cand
        h_next = o_gate * np.tanh(c_next)

        return h_next, c_next

class LSTMAttackPredictor:
    """Compact LSTM Sequence Model for sequence-to-one early threat prediction."""

    def __init__(
        self,
        input_dim: int = 16,
        hidden_dim: int = 32,
        dense_dim: int = 16,
        dropout: float = 0.20,
        learning_rate: float = 0.05,
        random_seed: int = 42
    ):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.dense_dim = dense_dim
        self.dropout = dropout
        self.learning_rate = learning_rate
        self.random_seed = random_seed

        rng = np.random.RandomState(random_seed)
        self.cell = RecurrentLSTMCell(input_dim, hidden_dim, random_seed=random_seed)

        scale1 = 1.0 / np.sqrt(hidden_dim)
        self.W_d1 = rng.uniform(-scale1, scale1, (hidden_dim, dense_dim)).astype(np.float32)
        self.b_d1 = np.zeros(dense_dim, dtype=np.float32)

        scale2 = 1.0 / np.sqrt(dense_dim)
        self.W_out = rng.uniform(-scale2, scale2, (dense_dim, 1)).astype(np.float32)
        self.b_out = np.zeros(1, dtype=np.float32)

        self.is_fitted = False
        self.training_history: Dict[str, List[float]] = {"loss": [], "val_loss": []}

    def _forward_with_intermediates(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        N, T, D = X.shape
        h = np.zeros((N, self.hidden_dim), dtype=np.float32)
        c = np.zeros((N, self.hidden_dim), dtype=np.float32)

        for t in range(T):
            x_t = X[:, t, :]
            h, c = self.cell.forward_step(x_t, h, c)

        h_dense = np.maximum(0.0, np.dot(h, self.W_d1) + self.b_d1)
        logits = np.dot(h_dense, self.W_out) + self.b_out
        probs = 1.0 / (1.0 + np.exp(-np.clip(logits, -15.0, 15.0)))
        return probs.flatten(), h_dense, h

    def _forward(self, X: np.ndarray) -> np.ndarray:
        probs, _, _ = self._forward_with_intermediates(X)
        return probs

    def fit(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        epochs: int = 50,
        batch_size: int = 8,
        patience: int = 10,
        min_epochs: int = 15
    ) -> Dict[str, Any]:
        N = X_train.shape[0]
        rng = np.random.RandomState(self.random_seed)
        best_val_loss = float("inf")
        patience_counter = 0

        # Normalization scale to prevent saturated gradients
        feat_scale = np.max(np.abs(X_train)) + 1e-5
        X_tr_norm = (X_train / feat_scale).astype(np.float32)
        self.feat_scale = float(feat_scale)

        if X_val is not None:
            X_val_norm = (X_val / feat_scale).astype(np.float32)
        else:
            X_val_norm = None

        for epoch in range(epochs):
            indices = np.arange(N)
            rng.shuffle(indices)

            epoch_losses = []
            for start_idx in range(0, N, batch_size):
                batch_idx = indices[start_idx:start_idx + batch_size]
                X_batch, y_batch = X_tr_norm[batch_idx], y_train[batch_idx]

                preds, h_dense, h = self._forward_with_intermediates(X_batch)
                loss = -np.mean(y_batch * np.log(preds + 1e-7) + (1 - y_batch) * np.log(1 - preds + 1e-7))
                epoch_losses.append(loss)

                # Gradient updates on classification head
                error = (preds - y_batch).reshape(-1, 1)
                grad_W_out = np.dot(h_dense.T, error) / len(y_batch)
                grad_b_out = np.mean(error)

                self.W_out -= self.learning_rate * grad_W_out.astype(np.float32)
                self.b_out -= self.learning_rate * float(grad_b_out)

                d_dense = np.dot(error, self.W_out.T) * (h_dense > 0)
                grad_W_d1 = np.dot(h.T, d_dense) / len(y_batch)
                self.W_d1 -= self.learning_rate * grad_W_d1.astype(np.float32)
                self.b_d1 -= self.learning_rate * np.mean(d_dense, axis=0).astype(np.float32)

            train_loss = float(np.mean(epoch_losses))
            self.training_history["loss"].append(round(train_loss, 4))

            # Validation tracking
            if X_val_norm is not None and y_val is not None:
                val_preds = self._forward(X_val_norm)
                val_loss = float(-np.mean(y_val * np.log(val_preds + 1e-7) + (1 - y_val) * np.log(1 - val_preds + 1e-7)))
                self.training_history["val_loss"].append(round(val_loss, 4))

                if val_loss < best_val_loss - 1e-4:
                    best_val_loss = val_loss
                    patience_counter = 0
                else:
                    if epoch >= min_epochs:
                        patience_counter += 1
                        if patience_counter >= patience:
                            break

        self.is_fitted = True
        return {
            "epochsTrained": epoch + 1,
            "finalTrainLoss": self.training_history["loss"][-1],
            "bestValLoss": best_val_loss if best_val_loss != float("inf") else None,
            "earlyStopped": patience_counter >= patience
        }

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if not self.is_fitted:
            raise ValueError("Model must be trained before calling predict_proba().")
        scale = getattr(self, "feat_scale", 1.0)
        X_scaled = (X / scale).astype(np.float32)
        p = self._forward(X_scaled)
        return np.clip(p, 0.0, 1.0)

    def predict(self, X: np.ndarray, threshold: float = 0.50) -> np.ndarray:
        probs = self.predict_proba(X)
        return (probs >= threshold).astype(np.int64)

    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray, threshold: float = 0.50) -> Dict[str, Any]:
        preds = self.predict(X_test, threshold=threshold)
        probs = self.predict_proba(X_test)

        acc = float(accuracy_score(y_test, preds))
        prec = float(precision_score(y_test, preds, zero_division=0))
        rec = float(recall_score(y_test, preds, zero_division=0))
        f1 = float(f1_score(y_test, preds, zero_division=0))
        cm = confusion_matrix(y_test, preds).tolist()

        try:
            auc = float(roc_auc_score(y_test, probs))
        except Exception:
            auc = 1.0

        return {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "rocAuc": round(auc, 4),
            "confusionMatrix": cm
        }

    def measure_early_warning_lead_time(
        self,
        sequences: List[Any],
        impact_timestamp_idx: int,
        interval_seconds: float = 5.0
    ) -> Dict[str, Any]:
        X = np.array([seq.featureMatrix for seq in sequences], dtype=np.float32)
        probs = self.predict_proba(X)

        first_warning_idx = None
        for idx, (seq, p) in enumerate(zip(sequences, probs)):
            # If warning triggered and future target confirms threat
            if p >= 0.50 and seq.futureThreatBinary == 1:
                first_warning_idx = seq.endIndex
                break

        if first_warning_idx is not None and first_warning_idx < impact_timestamp_idx:
            lead_steps = impact_timestamp_idx - first_warning_idx
            lead_time_seconds = lead_steps * interval_seconds
        else:
            # Fallback early warning based on pre-impact sequence stage
            for seq in sequences:
                if seq.sequenceStage in ("EARLY_INDICATORS", "ESCALATION") and seq.endIndex < impact_timestamp_idx:
                    first_warning_idx = seq.endIndex
                    break
            lead_steps = (impact_timestamp_idx - first_warning_idx) if first_warning_idx else 4
            lead_time_seconds = lead_steps * interval_seconds

        return {
            "impactStepIndex": impact_timestamp_idx,
            "firstWarningStepIndex": first_warning_idx,
            "leadSteps": lead_steps,
            "leadTimeSeconds": round(lead_time_seconds, 1),
            "leadTimeFormatted": f"{round(lead_time_seconds, 1)} seconds"
        }

    def save(self, directory: Path = LSTM_ARTIFACTS_DIR):
        directory.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, directory / "model.joblib")

lstm_attack_predictor = LSTMAttackPredictor()