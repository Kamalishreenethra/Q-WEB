# Sigstore Artifact and Signing Analysis

## 1. Overview & Purpose
The `SigstoreScanner` plugin extends SignChain with automated discovery and cryptographic classification for modern cloud-native software supply chain signing metadata. It parses Sigstore JSON bundles (v0.1, v0.2, v0.3), in-toto DSSE envelopes, and Cosign JSON artifacts to extract Fulcio X.509 short-lived signing certificates, OIDC identities (SAN Email/URI and custom workflow claims), Rekor transparency log inclusion proofs, and artifact integrity digests.

---

## 2. Conceptual Separation: Ecosystem vs. Cryptography

> [!IMPORTANT]
> **Mandatory Separation of Concerns**:
> Sigstore is a signing and transparency ecosystem, NOT a cryptographic algorithm.
> SignChain explicitly distinguishes:
> - **Signing Ecosystem**: `SIGSTORE`
> - **Cryptographic Algorithm**: `ECDSA-P256` / `RSA-2048` / `Ed25519`
> - **Quantum Status**: `VULNERABLE` / `QUANTUM_RESISTANT` / `UNKNOWN`

---

## 3. Supported Bundle Formats & Media Types

| Format | Media Type / Extension | Description |
|---|---|---|
| **Sigstore Bundle v0.3** | `application/vnd.dev.sigstore.bundle+json;version=0.3` | Modern Protobuf/JSON bundle with `x509CertificateChain`, `tlogEntries`, and `messageSignature`. |
| **Sigstore Bundle v0.1 / v0.2** | `application/vnd.dev.sigstore.bundle+json;version=0.2` | Earlier Sigstore bundle specification with `certificate` and `rekorBundle`. |
| **DSSE In-Toto Statement** | `.dsse`, `.intoto.jsonl` | Dual-signed envelope with embedded SLSA provenance / in-toto statement payload and subject digests. |
| **Cosign Legacy JSON** | `.json` with `rekorBundle` or `verificationMaterial` | Cosign signature payload containing PEM certificate and transparency log entry. |

---

## 4. Metadata Extraction Pipeline

```
     Sigstore Bundle (.sigstore.json / .bundle / .dsse)
                            │
                            ▼
                  JSON Schema Validator
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
  Artifact Digest   Signing Certificate    Rekor Evidence
   - Algorithm       - X.509 DER/PEM        - Log Index
   - Hash String     - Fulcio OIDC Claims   - Integrated Time
                     - SAN Email / URI      - Inclusion Proof
                            │               - Tree Size / Root Hash
                            ▼
            Shared Certificate Utility
                            │
                            ▼
          Deterministic CryptoClassifier
                            │
                            ▼
             Transparent RiskEngine
                            │
                            ▼
     Unified DependencyGraph & Prioritization
```

---

## 5. Fulcio Identity & OIDC Claims Extraction

When Fulcio short-lived certificates are present, SignChain inspects standard and custom extensions:
- **Subject Alternative Names (SAN)**:
  - `RFC822Name`: Signer email address (e.g. `ci-builder@signchain.org`).
  - `UniformResourceIdentifier`: Signer workflow URI (e.g. `https://github.com/org/repo/.github/workflows/deploy.yml@refs/heads/main`).
- **Custom Fulcio OIDC Extensions**:
  - `1.3.6.1.4.1.57264.1.1`: OIDC Issuer URL (e.g. `https://token.actions.githubusercontent.com`).
  - `1.3.6.1.4.1.57264.1.5`: GitHub Repository (e.g. `signchain/core`).
  - `1.3.6.1.4.1.57264.1.6`: GitHub Git Ref (e.g. `refs/heads/main`).
  - `1.3.6.1.4.1.57264.1.3`: GitHub Commit SHA.

---

## 6. Verification Statuses & Research Integrity Limitations

SignChain discovers, parses, extracts, and assesses Sigstore metadata in an offline mode. It explicitly distinguishes discovery from verification.

### Operations NOT Performed in Offline Analysis
- **No Full Rekor Merkle-Root Verification**: Offline analysis extracts inclusion proof metadata but does not cryptographically recompute or verify root hash consistency against live transparency logs.
- **No Live OIDC Identity Verification**: Identity claims (SAN email, workflow URI, repository) are extracted as observed metadata from unverified local certificates without querying identity provider endpoints.
- **No Full Cryptographic Signature Verification**: Digital signatures are detected and their algorithms parsed; end-to-end cryptographic verification is explicitly marked as not performed.

### Explicit Non-Collapsed States
- **Signature Status**: `SIGNATURE_PRESENT` vs `SIGNATURE_MISSING`.
- **Signature Verification**: `VERIFICATION_NOT_PERFORMED`.
- **Identity Status**: `OBSERVED`.
- **Transparency Evidence**: `PRESENT` vs `MISSING`.
- **Transparency Verification**: `NOT_VERIFIED`.

---

## 7. Offline-First Security & SSRF Safeguards

SignChain strictly executes in an **offline-first** mode:
1. **Zero Implicit Network Calls**: Standard `signchain scan` and `signchain sigstore` commands never contact Rekor or Fulcio servers.
2. **SSRF Protections**: If live online verification is invoked in future phases, requests are restricted to HTTPS, enforce connection and read timeouts, restrict maximum response sizes (10 MB), and explicitly forbid localhost/loopback or private RFC 1918 CIDR blocks.

---

## 8. Dependency Graph Integration

Sigstore artifacts populate the unified `DependencyGraph`:
- **Nodes**:
  - `NodeType.ARTIFACT`: The signed software bundle or payload.
  - `NodeType.CERTIFICATE`: The Fulcio short-lived signing certificate.
  - `NodeType.SIGNER`: The OIDC email or URI identity.
  - `NodeType.TRANSPARENCY_ENTRY`: The Rekor entry with log index and integrated timestamp.
- **Edges**:
  - `ARTIFACT` $\xrightarrow{\text{SIGNED_BY}}$ `CERTIFICATE`
  - `CERTIFICATE` $\xrightarrow{\text{BELONGS_TO}}$ `SIGNER`
  - `ARTIFACT` $\xrightarrow{\text{RECORDED_IN}}$ `TRANSPARENCY_ENTRY`
