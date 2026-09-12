# Day 104: XGBoost Gradient Boosting Baseline Classifier

## 1. Algorithmic Overview
XGBoost (Extreme Gradient Boosting) minimizes an empirical loss function through an additive tree expansion. At each iteration $t$, a new regression tree $f_t(\mathbf{x})$ is trained on the negative gradients (pseudo-residuals) of the previous ensemble:
$$\mathcal{L}^{(t)} = \sum_{i=1}^N \ell(y_i, \hat{y}_i^{(t-1)} + f_t(\mathbf{x}_i)) + \gamma T + \frac{1}{2} \lambda \sum_{j=1}^T w_j^2$$

Using second-order Taylor approximation:
$$g_i = \partial_{\hat{y}^{(t-1)}} \ell(y_i, \hat{y}^{(t-1)}), \quad h_i = \partial^2_{\hat{y}^{(t-1)}} \ell(y_i, \hat{y}^{(t-1)})$$
Optimal leaf weight $w_j^*$ for leaf node $j$ is analytically computed as:
$$w_j^* = -\frac{\sum_{i \in I_j} g_i}{\sum_{i \in I_j} h_i + \lambda}$$

## 2. Hyperparameters
- `n_estimators`: `100` (Number of boosting rounds).
- `max_depth`: `4` (Shallow trees to prevent overfitting on local network fluctuations).
- `learning_rate`: `0.1` (Shrinkage factor $\eta$).
- `subsample`: `0.8` (Fraction of training rows randomly sampled per iteration).
- `colsample_bytree`: `0.8` (Fraction of features randomly sampled per tree).
- `objective`: `binary:logistic` (Logistic loss for binary attack classification).
- `eval_metric`: `logloss` (Binary cross-entropy evaluation metric).
- `random_state`: `42` (Deterministic seed for reproducible gradient iterations).

## 3. Complete 5-Model Baseline Leaderboard
At the completion of Day 104, all five baseline classifiers are evaluated over the identical normalized test partition ($X_{\text{test}}, y_{\text{test}}$):
1. **Logistic Regression** (Linear baseline)
2. **Decision Tree** (Single non-linear baseline)
3. **Random Forest** (Bagging ensemble baseline)
4. **Support Vector Machine** (Maximum-margin RBF baseline)
5. **XGBoost** (Gradient boosting ensemble baseline)