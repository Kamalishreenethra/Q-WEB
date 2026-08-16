# PQC Migration Prioritization & Roadmap Engine - SignChain

## 1. Problem Statement: Risk vs. Migration Priority

A flat cryptographic inventory discovers which algorithms are vulnerable to cryptographically relevant quantum computers (CRQCs). However, knowing that an asset uses RSA-2048 is insufficient to determine **which asset to migrate first**.

Organizations operate under constrained engineering budgets and must sequence migrations logically. SignChain distinguishes between:

- **Security Risk (Phase 4)**: *How vulnerable is this cryptographic asset to quantum and classical attacks?*
- **Migration Priority (Phase 7)**: *In what operational sequence should this asset be transitioned to post-quantum cryptography?*

### The Double-Counting Solution
Phase 4 already evaluates composite risk using asset criticality, exposure, dependency reachability, validity horizon, and migration complexity. 

To prevent **double-counting**, Phase 7 consumes the **composite Phase 4 risk score** as a single factor and combines it with operational dimensions not present in Phase 4:

1. **PQC Readiness Urgency (Phase 6)**: `NOT_READY` assets require immediate planning urgency (100/100), whereas `PQC_READY` assets require zero migration urgency (0/100).
2. **Topological Betweenness Impact (Phase 5)**: Evaluates whether a signing authority acts as a structural bridge in the supply chain graph.
3. **Migration Complexity Penalty**: Subtracted from the priority score so that high-complexity targets do not artificially monopolize initial migration resources before prerequisites are ready.

---

## 2. Mathematical Model

The transparent migration priority score is calculated as:

$$\text{PriorityScore} = w_{\text{risk}} \cdot R + w_{\text{readiness}} \cdot U_{\text{readiness}} + w_{\text{dep}} \cdot I_{\text{dep}} - w_{\text{complexity}} \cdot \left(\frac{M_{\text{complexity}}}{2}\right)$$

### Default Configurable Weights

| Weight Parameter | Default Value | Description |
|---|---|---|
| `w_risk` | `0.40` | Composite Quantum Risk Score contribution |
| `w_readiness` | `0.30` | PQC Readiness Urgency (`NOT_READY` = 100, `PQC_READY` = 0) |
| `w_dep_impact` | `0.20` | Graph-derived downstream and bridge impact |
| `w_complexity` | `0.10` | Migration friction penalty (subtracted) |

> [!NOTE]
> Weights must strictly sum to 1.0 and are validated at runtime.

---

## 3. Priority Tiers & Thresholds

| Priority Tier | Threshold | Operational Meaning |
|---|---|---|
| `P1 — CRITICAL` | $\ge 75.0$ | Immediate migration planning and prerequisite dependency resolution required. |
| `P2 — HIGH` | $\ge 55.0$ | High-priority migration target scheduled for active testing and deployment. |
| `P3 — MEDIUM` | $\ge 35.0$ | Standard supply chain asset; migrate following upstream signing authority transition. |
| `P4 — LOW` | $< 35.0$ | Low operational risk or already quantum-resistant; maintain monitoring. |

---

## 4. Operational Migration Statuses

SignChain explicitly separates **Priority** from **Migratability**:

- `NOT_STARTED`: Discovery complete, no migration actions initiated.
- `PLANNING`: High priority, active roadmap formulation underway.
- `BLOCKED`: High priority, but unverified verification library or incompatible client blocks rollout.
- `READY_FOR_TESTING`: PQC candidate identified, ready for compatibility benchmarking.
- `READY_FOR_DEPLOYMENT`: Hybrid or PQC package validated, scheduled for release.
- `IN_PROGRESS`: Staged deployment across supply chain nodes.
- `VERIFICATION_REQUIRED`: Rollout complete, awaiting cryptographic audit verification.
- `COMPLETED`: Verified post-quantum cryptographic protection active.

---

## 5. Dependency-Aware Ordering & Conflict Detection

When generating the migration sequence:
1. **Cycle Detection**: Any cyclic dependencies in the supply chain graph are detected and flagged as `MIGRATION_CYCLE_DETECTED`.
2. **Topological Precedence**: Upstream root CAs and intermediate signers are ordered before downstream artifacts.
3. **Conflict Detection**: If a high-priority artifact ($P1/P2$) depends on an upstream certificate that is `NOT_READY`, SignChain outputs a `MIGRATION_DEPENDENCY_CONFLICT` alert.

---

## 6. Research Baseline Comparison

To support experimental evaluation of Hypothesis **H3** (*Dependency-aware analysis identifies high-impact migration targets that flat inventories miss*), SignChain includes `BaselinePrioritizer`:
- **Baseline**: Flat sorting solely by raw cryptographic risk score.
- **SignChain**: Graph-aware topological sequencing with betweenness centrality and conflict detection.
