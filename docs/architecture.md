# Architecture Documentation - SignChain

## 1. System Architecture Overview

SignChain is organized into a linear processing pipeline driven by modular, decoupled subsystems:

```
                 SOFTWARE INPUT
                       │
                       ▼
              ┌─────────────────┐
              │ Artifact Scanner │
              └────────┬────────┘
                       ▼
             ┌───────────────────┐
             │ Signature Extractor│
             └────────┬──────────┘
                      ▼
             ┌───────────────────┐
             │ Crypto Classifier │
             └────────┬──────────┘
                      ▼
             ┌───────────────────┐
             │ Dependency Graph  │
             └────────┬──────────┘
                      │
             ┌────────┴─────────┐
             ▼                  ▼
      Quantum Risk Engine   PQC Readiness
             │                  │
             └────────┬─────────┘
                      ▼
             ┌───────────────────┐
             │ Migration Engine  │
             └────────┬──────────┘
                      ▼
             ┌───────────────────┐
             │ Dashboard / API   │
             └───────────────────┘
```

---

## 2. Plugin-Based Scanner Subsystem

Every scanner module in SignChain inherits from an abstract base class `BaseScanner` ensuring uniform behavior and standard data normalization across signature types.

### Scanner Interface Contract
```python
from abc import ABC, abstractmethod
from typing import Dict, Any, List

class BaseScanner(ABC):
    
    @abstractmethod
    def can_handle(self, file_path: str) -> bool:
        """Determines if this scanner plugin can process the given artifact."""
        pass
        
    @abstractmethod
    def scan(self, file_path: str) -> Dict[str, Any]:
        """Extracts raw cryptographic signatures and certificate chains from the file."""
        pass
        
    @abstractmethod
    def normalize_result(self, raw_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Transforms raw scanner output into standardized SignChain schema items."""
        pass
```

### Supported Format Roadmap
- **X.509 Scanner** (Priority 1): Parses PEM, DER, CRT certificates using Python `cryptography`.
- **PE / Authenticode Scanner** (Priority 2): Parses WIN_CERTIFICATE structures and PKCS#7 signed data in Windows executables.
- **PGP Scanner** (Priority 3): Parses OpenPGP key rings and detached signatures.
- **Sigstore Scanner** (Priority 4): Parses Cosign bundles, Rekor entry proofs, and Fulcio OIDC certificates.
- **Container Scanner** (Priority 5): Extracts container layer manifests and associated OCI signatures.

---

## 3. Cryptographic Classifier

The Cryptographic Classifier deterministically analyzes extracted public keys and metadata to categorize algorithms and key strength:

- **Classical Algorithms**:
  - `RSA` (key sizes: 1024, 2048, 3072, 4096)
  - `ECDSA` (curves: P-256, P-384, P-521, secp256k1)
  - `EdDSA` (curves: Ed25519, Ed448)
- **Post-Quantum Algorithms**:
  - `ML-DSA` (Dilithium parameter sets: ML-DSA-44, ML-DSA-65, ML-DSA-87)
  - `SLH-DSA` (Sphincs+ parameter sets)
- **Hybrid Configurations**:
  - Combinations of classical + post-quantum signatures (e.g. RSA + ML-DSA dual signatures).

> [!IMPORTANT]
> Algorithm detection uses explicit object identifier (OID) and public key structure parsing. Machine learning or heuristic guesswork is strictly prohibited for standard certificate metadata parsing.

---

## 4. NetworkX Dependency Graph Model

SignChain uses **NetworkX** (`nx.DiGraph`) to construct a directed graph representing supply chain cryptographic relationships. For detailed specs, see [docs/dependency-graph.md](file:///c:/Users/HP/SignChain/docs/dependency-graph.md).

### Node Types
- `ARTIFACT` (software executable, library, package, container)
- `CERTIFICATE` (X.509 leaf certificate)
- `SIGNER` (developer identity, release key, OIDC identity, organization)
- `CA` (Root or Intermediate Certificate Authority)
- `PGP_KEY` (OpenPGP signing primary key or subkey)
- `SIGSTORE_BUNDLE` (Sigstore verification material bundle)
- `TRANSPARENCY_ENTRY` (Rekor transparency log entry)

### Edge Types
- `SIGNED_BY`: Artifact → Certificate / PGP_KEY / Signer
- `ISSUED_BY`: Certificate → CA / Intermediate CA
- `DEPENDS_ON`: Artifact → Artifact / Package
- `BELONGS_TO`: Key / Certificate → Signer / Identity
- `RECORDED_IN`: Artifact → Transparency Log Entry

### Impact Evaluation & Centrality
SignChain evaluates transitive downstream reachability ($N_{\text{downstream}}$), degree centrality, and betweenness centrality to identify high-impact root signing keys that affect multiple downstream artifacts.

---

## 5. Transparent Quantum Risk Engine

Risk scoring is computed transparently using a deterministic formula. Every factor score is normalized between 0 and 100:

$$\text{RiskScore} = w_c \cdot R_{\text{crypto}} + w_a \cdot C_{\text{asset}} + w_e \cdot E_{\text{exposure}} + w_h \cdot H_{\text{horizon}} + w_d \cdot I_{\text{dep}} + w_m \cdot M_{\text{complexity}}$$

### Configurable Factors
1. **Cryptographic Risk ($R_{\text{crypto}}$)**: RSA-2048 = 90, ECDSA-P256 = 85, RSA-4096 = 70, ML-DSA = 0.
2. **Asset Criticality ($C_{\text{asset}}$)**: Production root component vs dev utility.
3. **Exposure ($E_{\text{exposure}}$)**: Public internet facing vs internal air-gapped.
4. **Validity Horizon ($H_{\text{horizon}}$)**: Expiration timeframe relative to estimated CRQC window.
5. **Dependency Impact ($I_{\text{dep}}$)**: Transitive downstream node count in NetworkX graph.
6. **Migration Complexity ($M_{\text{complexity}}$)**: Legacy protocol constraints vs modern agile pipeline.

---

## 6. PQC Readiness Assessment Engine

The PQC Readiness Assessment Engine evaluates post-quantum migration preparedness across software supply chain artifacts. For detailed specs, see [docs/pqc-readiness.md](file:///c:/Users/HP/SignChain/docs/pqc-readiness.md).

### Readiness States
- `NOT_READY`: Uses quantum-vulnerable cryptography (e.g. RSA, ECDSA) with no PQC/hybrid deployment evidence.
- `PARTIALLY_READY`: PQC candidate identified or partial compatibility verified, deployment incomplete.
- `HYBRID_READY`: Uses dual classical + PQC hybrid signing configurations.
- `PQC_READY`: Uses standardized post-quantum algorithms (e.g., NIST FIPS 204 ML-DSA, FIPS 205 SLH-DSA) and passed verification.
- `UNKNOWN`: Missing cryptographic metadata.

### Migration Phases
- `PHASE_0_DISCOVERY`: Baseline signature discovery.
- `PHASE_1_ASSESSMENT`: Quantum risk & candidate PQC identification.
- `PHASE_2_COMPATIBILITY_TESTING`: Interoperability & performance benchmarking.
- `PHASE_3_HYBRID_OR_PQC_DEPLOYMENT`: Active rollout of hybrid/PQC signing.
- `PHASE_4_VERIFICATION`: Post-migration compliance & audit.
- `PHASE_5_CONTINUOUS_MONITORING`: Ongoing cryptographic agility tracking.

---

## 7. Migration Prioritization & Roadmap Engine

The Migration Prioritization Engine converts risk, graph centrality, readiness states, and operational complexity into a deterministic, explainable migration sequence without double-counting factors. For detailed specs, see [docs/migration-prioritization.md](file:///c:/Users/HP/SignChain/docs/migration-prioritization.md).

### Priority Tiers
- `P1 — CRITICAL` ($\ge 75.0$): Immediate prerequisite migration and planning required.
- `P2 — HIGH` ($\ge 55.0$): Scheduled for active testing and deployment.
- `P3 — MEDIUM` ($\ge 35.0$): Standard dependency migration.
- `P4 — LOW` ($< 35.0$): Low risk or already PQC ready.

---

## 8. PE / Authenticode Scanner Subsystem

The `PEScanner` statically parses Windows PE binaries (.exe, .dll, .sys) and extracts embedded Authenticode PKCS#7 certificate chains for cryptographic classification and graph integration. For detailed specs, see [docs/authenticode.md](file:///c:/Users/HP/SignChain/docs/authenticode.md).

---

## 9. Database & REST API Architecture

### Database Entities (SQLAlchemy / PostgreSQL / SQLite)
- `Artifact`: Metadata, hash, path, file size
- `Signature`: Extracted raw signature bytes, signature type
- `Certificate`: Issuer, subject, OIDs, valid dates, public key details
- `Signer`: Entity name, email, key fingerprint
- `Algorithm`: Algorithm family, key size, security level, quantum status
- `Dependency`: Upstream/downstream relations
- `Scan`: Scan ID, timestamp, runtime parameters, stats
- `Finding`: Cryptographic findings per scan
- `RiskAssessment`: Computed factor breakdowns & total score
- `MigrationPlan`: Ordered migration steps, target state, estimated effort

---

## 8. Directory Layout

```
SignChain/
├── AGENTS.md
├── README.md
├── pyproject.toml
├── .gitignore
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   ├── research-methodology.md
│   ├── benchmarking.md
│   ├── API.md
│   └── limitations.md
├── src/
│   └── signchain/
│       ├── __init__.py
│       ├── cli/
│       ├── scanners/
│       ├── classifiers/
│       ├── graph/
│       ├── risk/
│       ├── pqc/
│       ├── migration/
│       ├── db/
│       └── api/
├── tests/
│   ├── unit/
│   └── fixtures/
└── experiments/
    ├── configs/
    ├── raw/
    ├── processed/
    ├── results/
    └── plots/
```
