# Day 103: Support Vector Machine (SVM) Baseline Classifier

## 1. Mathematical Formulation
Support Vector Machines aim to solve a convex quadratic optimization problem to discover the maximum-margin separating hyperplane:
$$\min_{\mathbf{w}, b, \xi} \frac{1}{2} \|\mathbf{w}\|^2 + C \sum_{i=1}^N \xi_i$$
Subject to:
$$y_i (\mathbf{w}^T \phi(\mathbf{x}_i) + b) \ge 1 - \xi_i, \quad \xi_i \ge 0, \quad \forall i \in \{1, \dots, N\}$$

Where:
- $\mathbf{w}$ is the normal vector to the hyperplane.
- $C$ controls the trade-off between margin width and classification penalty.
- $\xi_i$ are slack variables permitting margin violations for soft margins.
- $\phi(\mathbf{x})$ maps the 20-dimensional normalized feature vector into an implicit high-dimensional space via the Radial Basis Function (RBF) kernel:
  $$K(\mathbf{x}_i, \mathbf{x}_j) = \exp(-\gamma \|\mathbf{x}_i - \mathbf{x}_j\|^2), \quad \gamma = \frac{1}{20 \cdot \text{Var}(X)}$$

## 2. Hyperparameters
- `kernel`: `rbf` (Enables non-linear separation boundaries).
- `C`: `1.0` (Standard inverse regularization factor).
- `gamma`: `scale` ($\frac{1}{n_{\text{features}} \cdot \text{Var}(X)}$).
- `class_weight`: `balanced` (Inversely weights samples by class frequencies to account for class imbalance).
- `probability`: `True` (Enables Platt scaling for continuous probability estimation).
- `random_state`: `42` (Ensures reproducible internal cross-validation splits for Platt scaling).

## 3. Computational Complexity & Scalability Profile
- **Training Time Complexity:** $\mathcal{O}(N_{\text{samples}}^2 \cdot d)$ to $\mathcal{O}(N_{\text{samples}}^3)$.
- **Inference Time Complexity:** $\mathcal{O}(N_{\text{support\_vectors}} \cdot d)$.
- **Memory Consumption:** Scales quadratically $\mathcal{O}(N^2)$ due to kernel matrix caching.
- **Production Assessment:** Effective on small-to-medium benchmark datasets ($N \le 50{,}000$). For massive-scale Digital Twin line-rate classification ($N > 1{,}000{,}000$), kernelized SVM typically requires replacement by linear approximations (`LinearSVC` / SGDClassifier) or gradient boosted trees (XGBoost).

## 4. Advantages & Limitations
### Advantages
- **Robust Against Overfitting:** Generalization error is bounded by margin width rather than feature dimensionality.
- **Effective in High Dimensions:** Performs reliably on dense continuous feature spaces.
- **Convex Global Minimum:** Guaranteed not to get trapped in local minima during gradient descent.

### Limitations
- **High Computational Overhead:** Substantially slower training times compared to Logistic Regression and Decision Trees.
- **Non-Parametric Feature Weights:** Unlike Logistic Regression, individual feature coefficients cannot be directly audited; model decisions rely on support vector combinations.
- **Strict Normalization Dependency:** Distance-based kernels fail when features are on drastically different scales (resolved by Phase 11 standard scaling).