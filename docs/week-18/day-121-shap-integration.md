# Day 121: SHAP Integration & Local Feature Contributions

## 1. Mathematical Foundation
SHAP decomposes any prediction $f(\mathbf{x})$ into additive feature attributions:
$$f(\mathbf{x}) = \phi_0 + \sum_{j=1}^M \phi_j(\mathbf{x})$$

Where:
- $\phi_0 = \mathbb{E}[f(\mathbf{X})]$ is the expected baseline model output over the training background distribution.
- $\phi_j(\mathbf{x})$ is the contribution of feature $j$.
- If $\phi_j > 0$, the observed value pushed the prediction toward the anomalous/threat class.
- If $\phi_j < 0$, the observed value reduced the threat score toward benign baseline.

## 2. Explainer Selection Matrix
- **`TreeExplainer`**: Exact, fast calculation for tree ensembles (`RandomForestClassifier`, `DecisionTreeClassifier`, `XGBClassifier`).
- **`LinearExplainer`**: Analytic feature attribution for linear models (`LogisticRegression`).
- **`Explainer` (General)**: Unified API with automatic model inspection.

## 3. Storage Specification
Each explained feature is stored as a tuple of:
$$\{\text{featureName}, \text{featureValue}, \text{shapValue}, \text{direction}, \text{rank}\}$$
Features are sorted by $|\phi_j|$ descending, and partitioned into Top Positive and Top Negative contributors.