# SignChain Large-Scale Empirical Benchmarking Specification & Results

## 1. Empirical Overview
This document consolidates the complete experimental results for the **SignChain Phase 14 Large-Scale Research Benchmark**, evaluating scalability, computational overhead, memory footprint, and prioritization quality across 6 controlled scenario families, 10 independent seeds ($42 \dots 51$), and workload sizes from $N=100$ to $N=25,000$ artifacts.

---

## 2. Experimental Hardware & Execution Environment
- **Operating System**: Microsoft Windows 11 Home (Build 10.0.26100)
- **Architecture**: AMD64 (x86_64)
- **CPU Core Topology**: 8 Logical Cores / 4 Physical Cores
- **System Memory (RAM)**: 15.34 GB
- **Python Runtime**: Python 3.13.5 (64-bit)
- **SignChain Version**: 0.1.0
- **Mathematical / Scientific Stack**: NumPy 2.2.3, SciPy 1.15.2, Matplotlib 3.10.0, NetworkX 3.4.2

---

## 3. Track A: Performance & Scalability Benchmark ($N=100 \dots 25,000$)

### 3.1 Measured Performance Data (1 Warm-up + 5 Measured Repetitions per Scale)

| Workload Scale ($N$) | Graph Nodes ($|V|$) | Graph Edges ($|E|$) | Pipeline Runtime Mean (s) | Median Runtime (s) | StdDev (s) | Migration Engine Time (s) | Peak Memory (MB) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **$N = 100$** | 120 | 121 | **0.0223** | 0.0212 | 0.0023 | 0.0202 | **0.1082** |
| **$N = 500$** | 600 | 605 | **0.0727** | 0.0770 | 0.0102 | 0.0673 | **0.5511** |
| **$N = 1,000$** | 1,200 | 1,216 | **0.1786** | 0.1887 | 0.0149 | 0.1637 | **1.1239** |
| **$N = 5,000$** | 6,000 | 6,061 | **0.7666** | 0.7471 | 0.0771 | 0.6979 | **6.2515** |
| **$N = 10,000$** | 12,000 | 12,078 | **1.7301** | 1.7001 | 0.0694 | 1.5512 | **12.5263** |
| **$N = 25,000$** | 30,000 | 29,958 | **4.8257** | 4.7163 | 0.2840 | 4.3530 | **30.3088** |

### 3.2 Complexity & Memory Analysis:
- **Empirical Scaling**: The measured implementation exhibited approximately near-linear empirical scaling over the evaluated workload range ($N=100 \dots 25,000$). From a theoretical perspective, reverse DAG reachability and topological sort operate with worst-case complexity $\mathcal{O}(V + E)$, while empirical timings reflect constant-factor Python overhead.
- **Memory Usage**: Memory usage increased approximately linearly over the tested workload range ($0.11\text{ MB}$ at $N=100$ to $30.31\text{ MB}$ at $N=25,000$).
- **Scope Limitation**: The implementation processed up to 25,000 synthetic artifacts in 4.83 seconds under the evaluated environment. These measurements demonstrate prototype scalability but do not establish production enterprise scalability.

---

## 4. Track B: Prioritization Quality & Inversion Minimization

### 4.1 Multi-Seed Aggregate Results ($N=100$, 10 Seeds per Scenario)

| Scenario Family | Baseline Inversions ($\mu \pm \sigma$) | SignChain Inversions ($\mu \pm \sigma$) | Inversion Reduction ($\Delta I$) | % Reduction | Paired Cohen's $d$ | Baseline $\text{Recall@}10$ | SignChain $\text{Recall@}10$ | Wilcoxon $p$-value ($n=10$, exact) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **`MIXED`** | $74.8 \pm 15.7$ | **$44.0 \pm 8.8$** | **$+30.80$** | **$41.2\%$** | **$1.88$** | $0.5400$ | **$0.7200$** | $p = 0.00195$ |
| **`DEPENDENCY_HUB`** | $84.1 \pm 17.4$ | **$51.2 \pm 13.6$** | **$+32.90$** | **$39.1\%$** | **$1.35$** | $0.4900$ | **$0.6600$** | $p = 0.00195$ |
| **`ANTI_CORRELATION`** | $92.6 \pm 11.8$ | **$51.4 \pm 18.1$** | **$+41.20$** | **$44.5\%$** | **$1.74$** | $0.4700$ | **$0.6900$** | $p = 0.00195$ |
| **`CRYPTO_SEVERE`** | $94.6 \pm 11.8$ | **$56.2 \pm 9.3$** | **$+38.40$** | **$40.6\%$** | **$2.10$** | $0.5000$ | **$0.7000$** | $p = 0.00195$ |
| **`ISOLATED_CRITICAL`** | $83.7 \pm 22.6$ | **$34.8 \pm 13.9$** | **$+48.90$** | **$58.4\%$** | **$2.26$** | $0.5600$ | **$0.8300$** | $p = 0.00195$ |
| **`MIGRATION_BLOCKED`**| $82.1 \pm 11.7$ | **$59.7 \pm 9.8$** | **$+22.40$** | **$27.3\%$** | **$1.74$** | $0.4900$ | **$0.6800$** | $p = 0.00195$ |

---

## 5. 4-Way Component Ablation Study

| Workload Scale | Metric | Baseline (Flat) | Model A (Crypto Only) | Model B (+Dependency) | Model C (+Readiness) | Model D (Full SignChain) |
|---|---|:---:|:---:|:---:|:---:|:---:|
| **$N = 100$** | Inversions ($I$) | $85$ | $75$ | $46$ | $47$ | **$49$** |
| | Spearman $\rho$ | $0.1865$ | $0.3083$ | **$0.6692$** | $0.6647$ | $0.6331$ |
| | $\text{HDR@}10$ | $0.5714$ | $0.5714$ | **$1.0000$** | **$1.0000$** | $0.8571$ |
| **$N = 500$** | Inversions ($I$) | $2,004$ | $1,675$ | $1,204$ | **$1,131$** | $1,169$ |
| | Spearman $\rho$ | $0.2657$ | $0.4213$ | $0.6572$ | **$0.6968$** | $0.6800$ |
| **$N = 1,000$** | Inversions ($I$) | $8,898$ | $7,505$ | $5,755$ | **$5,392$** | $5,431$ |
| | Spearman $\rho$ | $0.1620$ | $0.3331$ | $0.5675$ | **$0.5985$** | $0.5961$ |
| | Order Agreement ($\tau$) | $0.5529$ | $0.6229$ | $0.7108$ | **$0.7290$** | $0.7271$ |

### Explicit Ablation Finding:
Dependency-aware prioritization produced the largest marginal improvement over the crypto-only model in the evaluated ablation. Adding readiness improved ranking quality further, while the complete production configuration was slightly worse than the readiness ablation under the measured inversion metric.

### Explicit Negative Finding:
The full production configuration did not dominate every ablation variant under the inversion metric. In the evaluated workloads, dependency information produced the largest marginal improvement, while the addition of readiness and full migration factors produced smaller or occasionally negative marginal changes.

---

## 6. Sensitivity Analysis across Diverse Ground Truth Formulations ($N=500$)

| Ground Truth Configuration | Weighting ($\text{Crit} / \text{Vuln} / \text{Blast}$) | Baseline Inversions | SignChain Inversions | Baseline $\text{Recall@}10$ | SignChain $\text{Recall@}10$ | Spearman $\rho$ (SignChain) |
|---|---|:---:|:---:|:---:|:---:|:---:|
| **GT-A (Criticality Heavy)** | $60\% / 20\% / 20\%$ | $2,098$ | **$1,535$** | $0.1000$ | **$0.2000$** | **$0.5221$** |
| **GT-B (Vulnerability Heavy)**| $15\% / 70\% / 15\%$ | $2,008$ | **$1,115$** | $0.2000$ | **$0.6000$** | **$0.7048$** |
| **GT-C (Blast-Radius Heavy)** | $15\% / 15\% / 70\%$ | $1,998$ | **$701$** | $0.3000$ | **$0.8000$** | **$0.8523$** |
| **GT-D (Balanced Standard)**   | $35\% / 35\% / 30\%$ | $2,004$ | **$1,169$** | $0.2000$ | **$0.6000$** | **$0.6800$** |

---

## 7. Main Research Finding
In controlled synthetic supply-chain workloads, dependency-aware cryptographic migration prioritization substantially reduced priority inversions relative to flat cryptographic prioritization. Improvements varied across scenario families, with reductions ranging from **$27.3\%$ to $58.4\%$**. The largest gains occurred in scenarios where downstream impact materially affected migration urgency.

The implementation processed up to 25,000 synthetic artifacts in 4.83 seconds under the evaluated environment. These measurements demonstrate prototype scalability but do not establish production enterprise scalability.

---

## 8. Generated Publication Figures
The following 10 figures are generated directly from experimental result files in `research/plots/`:
1. `fig1_runtime_vs_size.png`: Pipeline runtime scalability from $N=100$ to $N=25,000$.
2. `fig2_memory_vs_size.png`: Peak memory consumption vs artifact count.
3. `fig3_graph_scalability.png`: Reverse DAG traversal and centrality computation time vs edge count.
4. `fig4_recall_comparison.png`: Baseline vs SignChain Top-10 recall by scenario family.
5. `fig5_inversions_by_size.png`: Priority inversions vs artifact count ($N=100 \dots 10,000$).
6. `fig6_critical_miss_rate.png`: Critical asset miss rate across scenario families.
7. `fig7_high_impact_recall.png`: High-impact dependency target recall ($\ge 5$ dependents).
8. `fig8_ablation_study.png`: 4-way ablation analysis on prioritization recall.
9. `fig9_scenario_inversions.png`: Inversion count reduction across all 6 scenario families.
10. `fig10_win_loss_distribution.png`: Overall head-to-head outcome distribution.
