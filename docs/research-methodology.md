# SignChain Research Methodology & Empirical Benchmarking Specification

## 1. Research Purpose & Overview
This document specifies the experimental design, hypotheses, evaluation metrics, scenario taxonomy, statistical framework, and threats to validity for empirical research on **SignChain** — a platform for automated cryptographic discovery and post-quantum cryptography (PQC) migration planning in software supply chains.

---

## 2. Research Questions (RQs)

- **RQ1 (Recall of Critical Migration Targets)**:
  Does graph-aware, multi-factor migration prioritization identify high-impact cryptographic migration targets more effectively than a flat cryptographic inventory?

- **RQ2 (Priority Inversion Reduction)**:
  Does supply-chain dependency awareness significantly reduce priority inversions (cases where an asset with higher blast radius is scheduled *after* an isolated asset)?

- **RQ3 (Computational Scalability & Overhead)**:
  What computational runtime and memory overhead is introduced by supply-chain dependency graph traversal and centrality calculation as artifact volume scales from $N=100$ to $N=10,000+$?

- **RQ4 (Boundary & Failure Scenarios)**:
  Under what topological or cryptographic configurations does dependency-aware prioritization fail, provide no advantage, or perform comparably to baseline heuristics?

---

## 3. Falsifiable Hypotheses

- **H1 (Top-K Recall Superiority)**:
  SignChain achieves statistically significant higher $\text{Recall@}K$ ($K \in \{5, 10, 20\}$) of independently defined high-urgency migration targets compared to the flat cryptographic baseline across mixed and hub-dominant supply chain graphs ($p < 0.05$).

- **H2 (Priority Inversion Minimization)**:
  SignChain generates fewer pairwise priority inversions relative to independent ground truth than the flat baseline ($p < 0.05$, Wilcoxon signed-rank test).

- **H3 (Practical Computational Scalability)**:
  The end-to-end SignChain analysis pipeline scales sub-quadratically ($O(V + E)$ or $O(V \log V)$) with respect to artifact count, maintaining execution times under 10 seconds for workloads up to $N=10,000$ artifacts.

- **H4 (Topology-Dependent Efficacy)**:
  The performance advantage of SignChain is positively correlated with graph density and hub skewness, and converges toward baseline parity in disjoint/isolated scenarios (e.g. Anti-Correlation and Isolated-Critical families).

---

## 4. Experimental Variables

### 4.1 Independent Variables (IVs)
1. **Prioritization Strategy**:
   - `Baseline` (Flat Cryptographic Inventory — key size and algorithm vulnerability only)
   - `Model A` (Ablation: Pure Cryptographic Risk Score)
   - `Model B` (Ablation: Cryptographic Risk + Downstream Dependency Impact)
   - `Model C` (Ablation: Cryptographic Risk + Dependency Impact + PQC Readiness Urgency)
   - `Model D` (Full Production SignChain: Multi-Factor Weighted + Graph Topology + Complexity Penalty)
2. **Workload Scale ($N$)**:
   - Small: $N = 20, 100$
   - Medium: $N = 500, 1,000$
   - Large: $N = 5,000, 10,000$
3. **Scenario Family**:
   - `DEPENDENCY_HUB`, `ISOLATED_CRITICAL`, `CRYPTO_SEVERE`, `MIGRATION_BLOCKED`, `MIXED`, `ANTI_CORRELATION`

### 4.2 Dependent Variables (DVs)
1. **Top-$K$ Recall ($\text{Recall@}5, \text{Recall@}10, \text{Recall@}20$)**
2. **Spearman Rank Correlation Coefficient ($\rho$) and $p$-value**
3. **Priority Inversion Count ($I$)**
4. **Critical Target Miss Rate ($\text{CMR@}10$)**
5. **High-Impact Dependency Target Recall ($\text{HDR@}10$)**
6. **Pairwise Migration Order Agreement ($\tau$)**
7. **End-to-End Execution Latency (seconds)**
8. **Peak Memory Consumption (MB)**

### 4.3 Controlled Variables (CVs)
- Randomization seed set: $\mathcal{S} = \{42, 43, 44, 45, 46, 47, 48, 49, 50, 51\}$
- Hardware environment: Fixed single-node multi-core architecture
- Cryptographic classifier parameters: Deterministic ASN.1/OID tables (FIPS 204 ML-DSA, FIPS 205 SLH-DSA, PKCS#1 RSA, RFC 5480 ECDSA)

---

## 5. Ground-Truth Independence & Conceptual Framework

### 5.1 Prevention of Circularity
To avoid methodological circularity, ground truth is constructed using an **independent Multi-Criteria Decision Analysis (MCDA)** model:

$$\text{Urgency}_{\text{GT}} = (C_{\text{service}} \times 0.35) + (V_{\text{crypto}} \times 35.0) + (\text{BlastRadius} \times 0.30) - P_{\text{blocked}}$$

Where:
- $C_{\text{service}} \in [0, 100]$: Average business criticality of consuming software services (declared independently during synthetic generation).
- $V_{\text{crypto}} \in \{0.1, 1.0\}$: Ground truth cryptographic vulnerability indicator ($1.0$ for vulnerable classical schemes, $0.1$ for validated PQC).
- $\text{BlastRadius} = \min(100.0, \log_2(1 + \text{dependents}) \times 12.5)$: Objective logarithmic dependency reachability.
- $P_{\text{blocked}} = 15.0$: Penalty applied if the asset has unresolvable external migration blockers.

### 5.2 Blind Evaluation Protocol
1. **Scenario Generation**: Construct synthetic supply chain graph and metadata.
2. **Scenario Freezing**: Serialize workload data into immutable structures.
3. **Ground Truth Generation**: Compute $\text{Urgency}_{\text{GT}}$ rankings.
4. **Baseline Execution**: Execute `FlatCryptographicBaseline` (isolated from graph and GT).
5. **SignChain Execution**: Execute `MigrationPrioritizationEngine` (isolated from GT).
6. **Metric Evaluation**: Calculate comparative metrics between generated rankings and GT.

---

## 6. Scenario Families Taxonomy

| Family | Description | Expected Winner / Dynamics |
|---|---|---|
| **A. Dependency Hub** | High downstream blast radius; hub signing keys affect 10–50+ downstream packages. | **SignChain Wins** (recognizes graph blast radius over local key size) |
| **B. Isolated Critical** | Very high business criticality on leaf nodes with zero downstream dependents. | **SignChain & Baseline Compete** (evaluates sensitivity to asset criticality) |
| **C. Crypto Severe** | High exposure vulnerable crypto (e.g. RSA-2048) on leaf nodes. | **Baseline Performs Well** (pure algorithm ranking aligns with urgency) |
| **D. Migration Blocked** | High blast radius but blocked by external compatibility / missing verifiers. | **SignChain Wins** (adjusts roadmap to avoid blocked bottlenecks) |
| **E. Mixed** | Realistic balanced distribution across all 5 ecosystems and 8 algorithms. | **SignChain Wins** (balanced multi-criteria optimization) |
| **F. Anti-Correlation** | Hubs use PQC (ML-DSA), whereas isolated leaves use vulnerable RSA-2048. | **Baseline Wins / Inconclusive** (tests whether SignChain over-prioritizes PQC hubs) |

---

## 7. Statistical Methodology

1. **Multi-Seed Testing**:
   Every experiment is replicated across 10 distinct, fully independent seeds ($\text{seed} \in [42 \dots 51]$).
2. **Hypothesis Testing**:
   Non-parametric **Wilcoxon Signed-Rank Test** for paired ordinal ranking deviations across seeds.
   - Null Hypothesis ($H_0$): The median difference in priority inversions between SignChain and Baseline is zero.
   - Significance threshold: $\alpha = 0.05$.
3. **Effect Size Reporting**:
   - Mean absolute reduction in priority inversions ($\Delta I = \bar{I}_{\text{base}} - \bar{I}_{\text{sc}}$).
   - Standardized effect size using Cohen's $d$: $d = \frac{\Delta I}{\sigma_{\Delta}}$.
   - Mean improvement in $\text{Recall@}10$.

---

## 8. Threats to Validity

### 8.1 Internal Validity
- *Threat*: Information leakage between ground truth and SignChain.
- *Mitigation*: Blind execution pipeline; ground truth is computed strictly before engine execution and uses a distinct MCDA scoring function.

### 8.2 External Validity
- *Threat*: Synthetic workloads may not perfectly represent real-world enterprise artifact graphs.
- *Mitigation*: Controlled distribution modeled across 5 major packaging ecosystems (X.509, Authenticode, OpenPGP, Sigstore, OCI Container) and 8 cryptographic standards. All claims are explicitly scoped to *controlled synthetic workloads*.

### 8.3 Construct Validity
- *Threat*: Priority inversion metrics might penalize acceptable alternative orderings.
- *Mitigation*: Complementing inversion counts with Spearman's $\rho$, Top-$K$ recall, and critical asset miss rates.

### 8.4 Conclusion Validity
- *Threat*: Overinterpreting small sample sizes or single-seed anomalies.
- *Mitigation*: Mandatory multi-seed evaluation ($N \ge 10$ independent seeds), reporting variances, effect sizes, and non-parametric $p$-values.
