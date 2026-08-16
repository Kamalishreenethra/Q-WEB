# AGENTS.md - SignChain Development Context & Tracking

## Project Purpose
**SignChain** is an automated discovery, cryptographic classification, and migration planning platform for post-quantum code signing in software supply chains.

The system addresses key post-quantum cybersecurity questions:
1. Where are digital signatures being used across software supply chain artifacts?
2. Which cryptographic algorithms and key parameters are active?
3. Which signatures are vulnerable to future cryptographically relevant quantum computers (CRQCs)?
4. Which certificates/signers have critical downstream impact across the dependency graph?
5. Which assets must be prioritized for migration?
6. What is the PQC readiness status of each asset (e.g. `NOT_READY`, `PARTIALLY_READY`, `HYBRID_READY`, `PQC_READY`)?
7. What topological migration sequence should an organization follow?
8. How can post-migration compliance and integrity be verified?

---

## Core Architecture Pipeline
```
       Software Input
             │
             ▼
     ┌───────────────┐
     │Artifact Scanner│ (Plugin interface: can_handle, scan, normalize_result)
     └───────┬───────┘
             ▼
    ┌─────────────────┐
    │Signature Extractor│
    └────────┬────────┘
             ▼
    ┌─────────────────┐
    │Crypto Classifier│ (Deterministically parses metadata: RSA, ECDSA, EdDSA, ML-DSA, SLH-DSA)
    └────────┬────────┘
             ▼
    ┌─────────────────┐
    │Dependency Graph │ (NetworkX model: Artifacts, Certificates, Signers, CAs, Dependencies)
    └────────┬────────┘
             │
    ┌────────┴────────┐
    ▼                 ▼
Quantum Risk Engine  PQC Readiness Engine
    │                 │
    └────────┬────────┘
             ▼
    ┌─────────────────┐
    │Migration Engine │ (Prioritization & topological roadmap generation)
    └────────┬────────┘
             ▼
    ┌─────────────────┐
    │ Dashboard / API │ (FastAPI backend + React/TS dashboard + Typer CLI)
    └─────────────────┘
```

---

## Key Design Principles & Constraints
1. **Zero Data Fabrication Policy**:
   - No mock dashboard stats, hardcoded fake benchmarks, or unverified claims.
   - If data has not yet been measured or calculated from actual input, render `"TBD — requires experiment"`.
2. **Deterministic Metadata Parsing**:
   - Rely on formal cryptographic parsing (OpenSSL, Python `cryptography`) for algorithm detection; do NOT use non-deterministic heuristic/ML guesswork when standard X.509 metadata exists.
3. **Transparent & Explainable Risk Model**:
   - Every risk score is computed using explicit, configurable weighted risk factors:
     `Risk = w_c * Risk_crypto + w_a * Criticality_asset + w_e * Exposure + w_h * Horizon + w_d * Impact_dep + w_m * Complexity_migration`
   - Every UI element displaying a score must render the full breakdown explaining *why* the score was given.
4. **Graph-Aware Dependency Prioritization**:
   - Migration priority is calculated dynamically using graph centrality and downstream transitive dependencies in NetworkX, avoiding flat static rules.
5. **Untrusted Input Security Baseline**:
   - Never execute scanned binaries. Perform strict static analysis only.
   - Guard against path traversal, archive bombs, command injection, malformed X.509 ASN.1 data, oversized inputs, and SSRF.

---

## Research Hypotheses Under Evaluation
- **H1**: SignChain discovers more signature dependencies than manual inventory.
- **H2**: SignChain accurately classifies supported signature algorithms without false positives.
- **H3**: Dependency-aware analysis identifies high-impact migration targets that flat inventories miss.
- **H4**: SignChain significantly reduces migration planning effort.
- **H5**: SignChain remains computationally practical as artifact volume increases.

---

## Development Phase Status

| Phase | Description | Status |
|---|---|---|
| **Phase 1** | Repository + environment setup + AGENTS.md + architecture docs + pyproject.toml | **COMPLETED** |
| **Phase 2** | X.509 scanner plugin implementation & CLI integration | **COMPLETED** |
| **Phase 3** | RSA / ECDSA / EdDSA / PQC cryptographic classifier | **COMPLETED** |
| **Phase 4** | Transparent Quantum Risk Engine | **COMPLETED** |
| **Phase 5** | NetworkX Dependency Graph Engine | **COMPLETED** |
| **Phase 6** | PQC Readiness Engine | **COMPLETED** |
| **Phase 7** | Migration Prioritization & Roadmap Engine | **COMPLETED** |
| **Phase 8** | PE / Authenticode signature scanner plugin | **COMPLETED** |
| **Phase 9** | PGP signature scanner plugin | **COMPLETED** |
| **Phase 10** | Sigstore signature scanner plugin | **COMPLETED** |
| **Phase 11** | Container image signature scanner plugin | **COMPLETED** |
| **Phase 12** | Database models (SQLAlchemy/SQLite/PostgreSQL) + FastAPI REST API | **COMPLETED** |
| **Phase 13** | React + TypeScript + Vite Dashboard | **COMPLETED** |
| **Phase 14** | Benchmarking suite & automated workload runner | **COMPLETED** |
| **Phase 15** | Security hardening & static analyzer defense validation | PENDING |
| **Phase 16** | Empirical research experiment framework execution | PENDING |
| **Phase 17** | Documentation, paper data generation (Tables 1 & 2, Figures 1 & 2) | PENDING |

---

## Important Commands

### Setup & Development
```powershell
# Create & activate virtual environment (if desired)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install package in editable mode
pip install -e .[dev]
```

### Testing & Quality Assurance
```powershell
# Run unit tests
pytest

# Run tests with verbose output
pytest -v
```

---

## Token Efficiency & Incremental Workflow Rules
- Do NOT rewrite existing working files unless requested.
- Do NOT generate fake data or hardcoded mock responses.
- Update `AGENTS.md` after completing each phase.
- Always run tests and verify runtime behavior before declaring a phase complete.
