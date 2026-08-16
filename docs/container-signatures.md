# OCI Container Image Signature Analysis

## 1. Overview & Purpose
The `ContainerScanner` plugin provides automated static discovery, cryptographic classification, and dependency mapping for OCI/Docker container image manifests and associated signature metadata (Cosign, Notary v2). It allows SignChain to evaluate container supply chain cryptographic security in an **offline-first** environment without executing containers or requiring local Docker daemons.

---

## 2. Security Baseline: Strict Static Analysis

> [!CAUTION]
> **Zero Container Execution Policy**:
> SignChain NEVER executes container images (`docker run`, `docker exec`, `containerd`, Kubernetes). Analysis is strictly limited to static JSON manifest parsing, layer digest inspection, and signature/certificate metadata extraction.

---

## 3. Supported Container Formats & Signing Ecosystems

| Format / Ecosystem | Media Type | Description |
|---|---|---|
| **OCI Image Manifest** | `application/vnd.oci.image.manifest.v1+json` | Standard OCI v1 manifest with config, layer digests, and annotations. |
| **OCI Image Index** | `application/vnd.oci.image.index.v1+json` | Multi-architecture container manifest list. |
| **Docker Schema 2** | `application/vnd.docker.distribution.manifest.v2+json` | Docker-compatible image manifest. |
| **Cosign Signatures** | `application/vnd.dev.cosign.simplesigning.v1+json` | Cosign signature layer with `dev.cosignproject.cosign/signature` and certificate annotations. |
| **Notary v2 (Notation)** | `application/vnd.cncf.notary.signature` | Notary v2 signature artifact descriptors referencing container subjects. |

---

## 4. Metadata Extraction Pipeline

```
  OCI Container Manifest / Metadata (.json / .oci.json)
                          │
                          ▼
            Manifest & Image Identifiers
             - Registry / Repository / Tag (Mutable)
             - Image Digest (Immutable Identifier)
             - Architecture / OS / Layer Count
                          │
            ┌─────────────┴─────────────┐
            ▼                           ▼
     Cosign Signatures          Notary v2 Artifacts
      - Signature Payload        - Artifact Descriptors
      - X.509 Certificate        - Subject References
            │
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

## 5. Image Digest vs. Mutable Tags

SignChain treats the **cryptographic image digest** (e.g., `sha256:d1d2d3...`) as the primary immutable identifier of a container artifact. Mutable tags (e.g., `:latest`, `:v1.4.2`) are extracted as contextual metadata but are never treated as stable cryptographic bounds.

---

## 6. Verification Statuses & Limitations

SignChain explicitly separates signature detection from full cryptographic validation:
- **Signature Status**: `SIGNATURE_PRESENT` vs `UNSIGNED`.
- **Signature Verification**: `VERIFICATION_NOT_PERFORMED`.
- **Cosign Support**: Discovers and extracts embedded PEM/DER certificates and signatures from layer annotations.
- **Notary Support**: Metadata discovery of Notary v2 artifact descriptors; full remote trust store policy validation is intentionally deferred.

---

## 7. Dependency Graph Integration

Container images integrate into SignChain's unified `DependencyGraph`:
- **Nodes**:
  - `NodeType.CONTAINER`: The container image identified by its immutable digest.
  - `NodeType.PACKAGE`: Container layer digests (`CONTAINS` edges).
  - `NodeType.CERTIFICATE`: The signing certificate (Cosign).
  - `NodeType.CA`: The issuing Certificate Authority.
- **Edges**:
  - `CONTAINER` $\xrightarrow{\text{SIGNED_BY}}$ `CERTIFICATE`
  - `CONTAINER` $\xrightarrow{\text{CONTAINS}}$ `PACKAGE` (Layer)
  - `CERTIFICATE` $\xrightarrow{\text{ISSUED_BY}}$ `CA`
