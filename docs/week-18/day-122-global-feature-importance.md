# Day 122: Global Feature Importance & Comparative Analysis

## 1. Global vs. Local Explanations
- **Local Explanation (Day 121):** Explains why a single instance $x$ was classified as an attack ($\hat{f}(x) = \phi_0 + \sum \phi_j$).
- **Global Feature Importance (Day 122):** Explains which features dictate model behavior across the entire population of network events.

## 2. Importance Formulations
1. **Tree-Based Gini Impurity Reduction (MDI):**
   $$I_{\text{MDI}}(j) = \sum_{t \in T_j} p(t) \Delta i(t)$$
   Measures the total decrease in node impurity weighted by sample probability across all splits on feature $j$.

2. **Linear Coefficient Magnitude:**
   $$I_{\text{Linear}}(j) = \frac{|\beta_j|}{\sum_{k=1}^M |\beta_k|}$$
   Measures the normalized sensitivity of the log-odds decision boundary to standard unit deviations in feature $j$.

3. **Global SHAP Importance:**
   $$I_{\text{SHAP}}(j) = \frac{1}{N} \sum_{i=1}^N |\phi_j^{(i)}|$$
   Averages the magnitude of local Shapley contributions across $N$ instances. Unlike MDI, SHAP reflects the actual change in predicted probability.

## 3. Method Divergence & Discrepancies
Native model importance and Global SHAP importance often produce different rankings:
- Features with extreme values in rare attack scenarios may have modest Gini splits, but massive local SHAP attributions when they occur.
- Correlated features may be arbitrarily split by tree algorithms (lowering individual MDI), whereas SHAP accurately distributes marginal game-theoretic credit.