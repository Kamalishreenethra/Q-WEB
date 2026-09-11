# SignChain — Controlled Multi-Scan Demonstration Corpus Report

## 1. Executive Summary
A small, controlled, reproducible demonstration corpus consisting of 12 distinct X.509 public certificates was created in [`research/demo_corpus/certificates/`](file:///C:/Users/HP/SignChain-RealWorld/research/demo_corpus/certificates/) and ingested through the **real SignChain scanner/CLI/ingestion pipeline**.

Every scan record was processed via `X509Scanner` and `IngestionService`, computing full cryptographic classification, transparent quantum risk scores, PQC readiness states, NetworkX graph topologies, and topological migration priorities.

---

## 2. Ingested Demonstration Corpus

| # | Filename | Common Name | Algorithm | Key Size / Curve | CA Status |
|---|---|---|---|---|---|
| 1 | `demo_root_ca_rsa4096.pem` | SignChain Demo Enterprise Root CA | RSA | 4096-bit | `CA:TRUE` |
| 2 | `demo_intermediate_ca_rsa3072.pem` | SignChain Demo Code Signing Intermediate CA | RSA | 3072-bit | `CA:TRUE` |
| 3 | `demo_code_signing_rsa2048_a.pem` | SignChain Demo Release Signing Alpha | RSA | 2048-bit | `CA:FALSE` |
| 4 | `demo_code_signing_rsa2048_b.pem` | SignChain Demo CI/CD Pipeline Signer | RSA | 2048-bit | `CA:FALSE` |
| 5 | `demo_code_signing_rsa3072.pem` | SignChain Demo Package Publisher 3072 | RSA | 3072-bit | `CA:FALSE` |
| 6 | `demo_code_signing_rsa4096.pem` | SignChain Demo Kernel Driver Publisher | RSA | 4096-bit | `CA:FALSE` |
| 7 | `demo_root_ca_ecdsa_p384.pem` | SignChain Demo ECC Root Authority | ECDSA | SECP384R1 (P-384) | `CA:TRUE` |
| 8 | `demo_code_signing_ecdsa_p256.pem` | SignChain Demo Container Signer P256 | ECDSA | SECP256R1 (P-256) | `CA:FALSE` |
| 9 | `demo_code_signing_ecdsa_p384.pem` | SignChain Demo Microservice Attestation Key | ECDSA | SECP384R1 (P-384) | `CA:FALSE` |
| 10 | `demo_code_signing_ecdsa_p521.pem` | SignChain Demo High-Assurance Signer P521 | ECDSA | SECP521R1 (P-521) | `CA:FALSE` |
| 11 | `demo_code_signing_ed25519.pem` | SignChain Demo Git Commit Signer Ed25519 | Ed25519 | Ed25519 | `CA:FALSE` |
| 12 | `demo_timestamping_rsa2048.pem` | SignChain Demo Authenticode Timestamp Authority | RSA | 2048-bit | `CA:FALSE` |

*Note: All private keys were generated in-memory and immediately discarded. Zero private keys are stored in the repository.*

---

## 3. Database Record Counts

All rows were created by the real ingestion engine:

| Database Table | Row Count |
|---|---|
| `scans` | **13** (1 previous baseline + 12 demo scans) |
| `artifacts` | **13** |
| `certificates` | **13** |
| `signatures` | **13** |
| `risk_assessments` | **13** |
| `pqc_readiness_assessments` | **13** |
| `migration_assessments` | **13** |
| `dependency_nodes` | **26** |
| `dependency_edges` | **13** |

---

## 4. API Endpoints Verification

All REST API endpoints report accurate counts through standard pagination parameters (`total: 13`):

| Endpoint | HTTP Status | Total Records | Items Returned | Default Page Size |
|---|---|---|---|---|
| `GET /scans` | `200 OK` | 13 | 13 | 50 |
| `GET /artifacts` | `200 OK` | 13 | 13 | 50 |
| `GET /certificates` | `200 OK` | 13 | 13 | 50 |
| `GET /risk` | `200 OK` | 13 | 13 | 50 |
| `GET /pqc` | `200 OK` | 13 | 13 | 50 |
| `GET /migration` | `200 OK` | 13 | 13 | 50 |
| `GET /graph/scan/{id}` | `200 OK` | - | 2 nodes, 1 edge per scan | - |

---

## 5. Frontend & UI Verification

The React frontend presents the authentic multi-scan database records across all views:
1. **Overview Dashboard:** Aggregates real metrics: 13 Total Assets, 13 Signing Identities, 13 Quantum-Vulnerable Keys, 0 PQC-Ready, Top Migration Targets ladder, and Recent Scan feed.
2. **Scan History:** Lists all 13 discovery scans ordered newest-first with duration, status, and artifact count.
3. **Asset Inventory:** Displays all 13 discovered artifacts with ecosystem badges, search, and page size filters (10/20/50).
4. **Certificate Intelligence:** Shows monospace SHA-256 fingerprints, copy-to-clipboard, key sizes, and CA indicators.
5. **Quantum Risk Analytics:** Multi-factor breakdown for all 13 assets with transparent formula calculation.
6. **PQC Readiness Engine:** Classifies all 13 assets under NIST FIPS 204/205 guidance.
7. **Migration Priority:** Prioritizes assets across P1–P4 tiers with action recommendations.
8. **3D Dependency Graph:** Live WebGL 3D graph with scan selector dropdown allowing inspection of any scan's cryptographic topology.

---

## 6. Test Isolation Verification

- **Backend Pytest:**
  ```
  ======================= 182 passed, 1 warning in 9.48s ========================
  ```
- **Database Non-Contamination Check:**
  - Record count before pytest: `scans: 13, artifacts: 13, certificates: 13`
  - Record count after pytest: `scans: 13, artifacts: 13, certificates: 13`
  - **Zero test records leaked into the real application database.**

---

## 7. Frontend Build Result

```
> tsc && vite build
✓ 1588 modules transformed.
dist/index.html                   1.22 kB
dist/assets/index-BfrMxYfY.css   13.98 kB
dist/assets/index-BrG2_3Be.js   773.30 kB
✓ built in 4.12s with 0 TypeScript errors and 0 Vite errors.
```
