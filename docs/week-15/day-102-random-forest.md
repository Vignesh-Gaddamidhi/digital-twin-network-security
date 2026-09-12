# Day 102: Random Forest Ensemble Baseline

## 1. Ensemble Architecture & Variance Reduction
A single decision tree is sensitive to minor variations in network flow observations. Random Forest stabilizes generalization by training an ensemble of $B$ decorrelated decision trees:
- **Bootstrap Sampling:** Each tree $b \in \{1, \dots, B\}$ is fitted on a bootstrap sample $D_b$ sampled with replacement from $D_{\text{train}}$.
- **Feature Decorrelation:** At each candidate split, candidate features are restricted to a random subset $m \ll p$. For our 20-dimensional vector:
  $$m = \lfloor\sqrt{20}\rfloor = 4$$
  This prevents strong features (like volumetric packet rates) from dominating every top split across all trees.

## 2. Model Hyperparameters
- `n_estimators`: `100` (Ensemble tree count balancing variance reduction and training throughput).
- `max_depth`: `8` (Constrained tree depth preventing memorization of small burst instances).
- `min_samples_split`: `4` (Minimum samples needed to split an internal node).
- `min_samples_leaf`: `2` (Guarantees leaf nodes represent at least two distinct observations).
- `max_features`: `sqrt` (Samples 4 candidate features per node).
- `class_weight`: `balanced` (Inversely proportional to class frequencies).
- `oob_score`: `True` (Computes Out-Of-Bag generalization error without test set leakage).
- `random_state`: `42` (Ensures deterministic bootstrap draws).

## 3. Ensemble Feature Importance (MDI)
The ensemble feature importance averages the Gini impurity decrease across all $B$ trees:
$$\text{Importance}_{\text{RF}}(f_j) = \frac{1}{B} \sum_{b=1}^{B} \text{Importance}_{T_b}(f_j)$$

## 4. Multi-Model Baseline Comparison
Evaluation metrics are compared across the three established baselines:
- Logistic Regression (Linear boundary baseline)
- Decision Tree (Single non-linear tree baseline)
- Random Forest (Bagged non-linear ensemble)