# Day 101: Decision Tree Baseline Classifier

## 1. Algorithmic Overview
The Decision Tree partitions the 20-dimensional continuous feature space by greedily selecting feature thresholds that maximize the reduction in Gini Impurity:
$$I_G(p) = 1 - \sum_{k=0}^{1} p_k^2$$
$$\Delta I_G = I_G(D) - \left( \frac{|D_L|}{|D|} I_G(D_L) + \frac{|D_R|}{|D|} I_G(D_R) \right)$$

Unlike Logistic Regression's single linear hyperplane, the Decision Tree establishes axis-aligned hyperplanes, capturing non-linear threshold rules (e.g., volumetric floods vs. low-rate port sweeps).

## 2. Model Hyperparameters
- `criterion`: `gini` (Computationally efficient impurity metric).
- `max_depth`: `6` (Pruning limit to guard against deep overfitting on localized noise).
- `min_samples_split`: `4` (Minimum samples required to attempt internal node splitting).
- `min_samples_leaf`: `2` (Ensures terminal leaves generalize across at least two samples).
- `class_weight`: `balanced` (Inversely proportional to binary class frequencies).
- `random_state`: `42` (Deterministic reproducibility).

## 3. Feature Importance (Mean Decrease in Impurity)
Feature importance represents the total normalized reduction of the Gini criterion brought by each feature across all tree splits:
$$\text{Importance}(f_j) = \frac{\sum_{t \in T, v(t)=f_j} p(t) \Delta I_G(t)}{\sum_{t \in T} p(t) \Delta I_G(t)}$$

*Note: Feature importance indicates predictive utility within the trained tree topology, not causal proof.*