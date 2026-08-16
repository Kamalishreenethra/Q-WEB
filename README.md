# SignChain

> **SignChain: Automated Discovery and Migration Planning for Post-Quantum Code Signing in Software Supply Chains**

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## 1. Problem Statement

Modern software supply chains rely extensively on digital signatures (X.509 certificates, PE Authenticode, PGP keys, Sigstore signatures, container image signatures) to establish artifact authenticity, provenance, and software integrity. 

However, standard public-key signature algorithms—primarily **RSA** and **ECDSA** (Elliptic Curve Digital Signature Algorithm)—depend on mathematical problems (integer factorization and discrete logarithms) that can be solved in polynomial time by a future **Cryptographically Relevant Quantum Computer (CRQC)** using Shor's algorithm.

Organizations currently face major operational hurdles in preparing software supply chains for post-quantum cryptography (PQC):
1. **Lack of Cryptographic Visibility**: Organizations do not know where all digital signatures are deployed across binaries, containers, releases, and third-party dependencies.
2. **Flat Inventory Inadequacy**: Standard Software Bill of Materials (SBOM) tools treat artifacts as flat lists, missing downstream topological impact when a root certificate or key requires migration.
3. **Migration Prioritization Ambiguity**: Without graph-aware dependency modeling and explainable risk metrics, security teams cannot determine which signatures to migrate first to prevent supply chain disruption.

---

## 2. Solution Overview

**SignChain** is a software-only cybersecurity platform designed to discover, classify, analyze, and plan the post-quantum migration of digital signatures across software supply chains.

SignChain processes raw software artifacts and generates an actionable, graph-driven post-quantum migration roadmap through a nine-stage pipeline:

```
Software Artifacts
       ↓
Artifact Discovery
       ↓
Signature Extraction
       ↓
Cryptographic Classification
       ↓
Dependency Mapping
       ↓
Quantum Risk Assessment
       ↓
PQC Readiness Assessment
       ↓
Migration Prioritization
       ↓
Migration Roadmap
       ↓
Dashboard + Reports
```

---

## 3. Architecture

SignChain uses a modular, plugin-based architecture designed for low overhead and strict static analysis safety:

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

For full architectural specs, see [docs/architecture.md](file:///c:/Users/HP/SignChain/docs/architecture.md).

---

## 4. Installation & Setup

### Requirements
- **Python**: 3.10+
- **Git**: 2.x+
- **Node.js**: 20+ (for React Dashboard, in Phase 13)

### Installation
```powershell
# Clone workspace repository
git clone https://github.com/adpooja-2007/QNET-.git signchain
cd signchain

# Create virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install in editable mode with development dependencies
pip install -e .[dev]
```

---

## 5. Usage & CLI

SignChain provides a Typer-based command-line interface:

```powershell
# Scan a single certificate or artifact (Phase 1 CLI foundation)
signchain scan certificate.pem

# Complete workflow commands (implemented incrementally across phases):
signchain analyze <scan-id>
signchain graph <scan-id>
signchain risk <scan-id>
signchain roadmap <scan-id>
signchain report <scan-id>
signchain benchmark <dataset>
```

---

## 6. Supported Signature Formats

SignChain introduces signature formats incrementally via plugin modules:

1. **Priority 1**: X.509 Certificates (`.pem`, `.crt`, `.der`)
2. **Priority 2**: PE / Authenticode Binaries (`.exe`, `.dll`, `.sys`)
3. **Priority 3**: PGP Signatures (`.asc`, `.gpg`, detached signatures)
4. **Priority 4**: Sigstore Artifacts (OIDC tokens, Rekor transparency logs, Cosign bundles)
5. **Priority 5**: Container Signatures (OCI images, Docker signatures)

---

## 7. Dashboard Overview

The SignChain Dashboard (built with React, TypeScript, and Vite) provides interactive, real-time visualization of supply chain cryptographic health:
- **Overview**: Active inventory, quantum vulnerability ratios, high-impact signers.
- **Artifact Explorer**: Deep inspection of extracted signatures, key sizes, and validity windows.
- **Cryptographic Inventory**: Algorithm distributions (RSA, ECDSA, EdDSA, ML-DSA, Hybrid).
- **Dependency Graph**: Interactive network visualizer detailing root CAs, intermediate signers, and child artifacts.
- **Risk Analysis**: Transparent breakdown explaining exact risk factors per artifact.
- **PQC Migration**: Phased, topological migration sequences with blocker identification.
- **Reports**: Export capabilities in JSON, CSV, and PDF formats.

> [!NOTE]
> SignChain strictly enforces zero data fabrication. Dashboard views show only verified scan data or explicit `"TBD — requires experiment"` place-holders.

---

## 8. Security Policy & Threat Model

Scanned software artifacts are treated as **UNTRUSTED INPUT**. 

- **No Execution**: SignChain uses static analysis only. Scanned binaries are never executed.
- **Input Sanitization & Limits**: Bounds checking on file sizes, recursion depths (anti-archive bomb), and strict path sanitization (anti-path traversal).
- **No Command Injection**: No shell execution of input strings.

For detailed security boundaries, see [docs/threat-model.md](file:///c:/Users/HP/SignChain/docs/threat-model.md).

---

## 9. Testing & Quality Assurance

SignChain enforces mandatory unit and integration testing across every subsystem:

```powershell
# Run the complete test suite
pytest

# Run tests with coverage report
pytest --cov=signchain tests/
```

Test fixtures cover valid/invalid X.509 certs, RSA/ECDSA/PQC keys, malformed files, detached signatures, and multi-node dependency chains.

---

## 10. Research Methodology & Hypotheses

SignChain is designed as a research-grade prototype to evaluate five core research hypotheses:

- **H1**: SignChain discovers more signature dependencies than manual software supply chain inventory.
- **H2**: SignChain accurately classifies supported classical and PQC signature algorithms without false positives.
- **H3**: Dependency-aware analysis identifies high-impact migration targets that flat inventories miss.
- **H4**: SignChain reduces post-quantum migration planning effort compared to unassisted audit.
- **H5**: SignChain remains computationally practical as artifact volume increases.

Experimental evidence is logged under `experiments/` and used to populate empirical evaluation tables and figures in research documentation.

---

## 11. Limitations & Non-Goals

### What SignChain Is NOT
- Not a new encryption or digital signature algorithm implementation.
- Not a claim that quantum computers currently break RSA today.
- Not an automated live patching system that overwrites production signatures without review.
- Not a generic intrusion detection system (IDS) or endpoint detection and response (EDR) agent.

---

## 12. Future Work

- Expansion to post-quantum hybrid certificate verification (NIST SP 800-227 / RFC 9370).
- Support for hardware security module (HSM) signing key discovery.
- Integration with SLSA provenance attestations and in-toto supply chain layouts.
