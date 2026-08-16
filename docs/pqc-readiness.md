# PQC Readiness Assessment Engine Documentation - SignChain

## 1. Executive Overview

Identifying vulnerable signature algorithms (e.g., RSA-2048, ECDSA-P256) is only the first step in post-quantum cybersecurity risk management. To plan an enterprise migration, organizations must understand:
1. **PQC Readiness State**: How prepared is each artifact or system for post-quantum key transition?
2. **Candidate Replacement Options**: Which NIST standardized PQC signature scheme (e.g. ML-DSA, SLH-DSA) is best suited for this cryptographic role?
3. **Migration Blockers**: What operational constraints (e.g., verification library support, client compatibility) block immediate deployment?
4. **Current Migration Phase**: What is the next logical step in the organizational roadmap?

**SignChain** addresses these questions through an **evidence-based PQC Readiness Assessment Engine**.

> [!IMPORTANT]
> *Decision-Support Disclaimer*: The PQC Readiness Assessment Engine is an automated decision-support guidance mechanism and does NOT constitute a guarantee of future security or compliance. SignChain does not implement cryptographic primitives from scratch nor claim that any single PQC algorithm is universally correct.

> [!NOTE]
> *Research Significance Statement*: The PQC Readiness Engine moves SignChain from flat "cryptographic inventory" toward actionable, graph-aware "PQC migration assessment." The research goal is to evaluate experimentally whether combining signature discovery, graph analysis, readiness assessment, and migration roadmap generation yields superior migration efficiency compared to unassisted audit.

---

## 2. Readiness States

SignChain categorizes artifacts into five deterministic readiness states:

| Readiness State | Operational Definition |
|---|---|
| `NOT_READY` | Uses quantum-vulnerable public-key cryptography (e.g. RSA, ECDSA, EdDSA) with no identified PQC or hybrid deployment evidence. |
| `PARTIALLY_READY` | PQC migration path or candidate implementation has been identified, but verification and deployment are incomplete. |
| `HYBRID_READY` | A dual classical + PQC hybrid signing configuration (e.g. RSA + ML-DSA) has been observed or validated. |
| `PQC_READY` | Signing mechanism uses a standardized post-quantum signature algorithm (e.g., NIST FIPS 204 ML-DSA, FIPS 205 SLH-DSA) and passed verification checks. |
| `UNKNOWN` | Insufficient cryptographic metadata or unclassifiable artifact structure. |

---

## 3. Migration Phases

The engine maps each artifact to a recommended phase in the post-quantum migration lifecycle:

```
  ┌───────────────────────┐
  │  PHASE_0_DISCOVERY    │  Baseline artifact signature discovery
  └───────────┬───────────┘
              ▼
  ┌───────────────────────┐
  │  PHASE_1_ASSESSMENT   │  Quantum risk & candidate PQC identification
  └───────────┬───────────┘
              ▼
  ┌───────────────────────┐
  │PHASE_2_COMPATIBILITY  │  Interoperability & performance benchmarking
  └───────────┬───────────┘
              ▼
  ┌───────────────────────┐
  │ PHASE_3_DEPLOYMENT    │  Dual/hybrid or PQC signature rollout
  └───────────┬───────────┘
              ▼
  ┌───────────────────────┐
  │ PHASE_4_VERIFICATION  │  Post-migration verification & audit
  └───────────┬───────────┘
              ▼
  ┌───────────────────────┐
  │PHASE_5_MONITORING     │  Continuous cryptographic agility tracking
  └───────────────────────┘
```

---

## 4. Evidence Classification Model

To preserve research credibility and prevent unfounded security claims, SignChain explicitly categorizes every assessment data point into three evidence levels:

- `OBSERVED`: Empirical facts directly parsed from standard X.509 metadata (e.g. `Public Key = RSA-2048`, `Expiration = 2027`).
- `INFERRED`: Technical conclusions derived from cryptographic standards (e.g. `Quantum Vulnerable = True` inferred from `RSA-2048`).
- `UNKNOWN`: Missing or unmeasured operational state (e.g. whether production client software supports ML-DSA signature verification).

---

## 5. Standardized PQC Knowledge Base

SignChain maintains a structured PQC knowledge base (`config/pqc_algorithms.yaml`) listing standardized post-quantum algorithms:

- **NIST FIPS 204 (ML-DSA)**:
  - `ML-DSA-44` (NIST Category 1 - AES-128 Equivalent)
  - `ML-DSA-65` (NIST Category 3 - AES-192 Equivalent; **Primary Recommended Target**)
  - `ML-DSA-87` (NIST Category 5 - AES-256 Equivalent; High Security Root CAs)
- **NIST FIPS 205 (SLH-DSA)**:
  - `SLH-DSA-SHA2-128f` (NIST Category 1 - Stateless Hash-Based Conservative Backup)
  - `SLH-DSA-SHA2-256f` (NIST Category 5 - Stateless Hash-Based High Security Backup)

---

## 6. Compatibility Dimensions

SignChain evaluates four operational compatibility dimensions:

| Dimension | Possible Values | Description |
|---|---|---|
| `artifact_format` | `SUPPORTED`, `PARTIAL`, `UNKNOWN`, `UNSUPPORTED` | Capability of file format (e.g. X.509 PEM/DER, PE Authenticode) to embed PQC keys. |
| `verification_support` | `SUPPORTED`, `PARTIAL`, `UNKNOWN`, `UNSUPPORTED` | Verification library support for PQC signatures. |
| `deployment_support` | `SUPPORTED`, `PARTIAL`, `UNKNOWN`, `UNSUPPORTED` | Production deployment infrastructure compatibility. |
| `interoperability` | `SUPPORTED`, `PARTIAL`, `UNKNOWN`, `UNSUPPORTED` | Downstream client ecosystem interoperability. |

---

## 7. Migration Blockers

For vulnerable artifacts (`NOT_READY`), SignChain automatically identifies specific operational blockers, such as:
- Production verification library support for PQC signatures is unverified.
- Downstream client ecosystem interoperability not verified.
- PQC performance and signature size impact benchmark not completed.

---

## 8. CLI Usage & Output

```powershell
# Run PQC readiness assessment on scan result or cert
signchain pqc scan_result.json

# Export machine-readable JSON
signchain pqc scan_result.json --json
```

---

## 9. Limitations & Non-Goals

- **No Primitives Implementation**: SignChain evaluates readiness and plans migration; it does not implement custom cryptographic primitives or replace production cryptographic libraries.
- **No Automatic Patching**: SignChain provides decision-support reports and candidate targets; it does not automatically modify or re-sign production binaries without security engineer review.
