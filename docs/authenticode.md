# PE / Authenticode Signature Scanner Documentation - SignChain

## 1. Executive Overview

Software supply chains rely heavily on Windows Portable Executable (PE) binaries (.exe, .dll, .sys) signed using Microsoft **Authenticode**. While X.509 certificate scanning provides baseline cryptographic knowledge, real supply chain security requires discovering where digital signatures are embedded within compiled binary artifacts.

**SignChain** extends its discovery pipeline to Windows PE binaries via the plugin-based `PEScanner`, integrating directly with the Cryptographic Classifier, Quantum Risk Engine, Dependency Graph, PQC Readiness Engine, and Migration Prioritization Engine.

---

## 2. Security Architecture & Threat Model

> [!CAUTION]
> **Untrusted Input Baseline**: PE binaries scanned by SignChain must be treated as potentially hostile or untrusted input. SignChain strictly performs **safe static analysis**.

### Static Analysis Constraints
- **Zero Execution Policy**: Target executables and libraries are never loaded (`LoadLibrary`), executed (`CreateProcess`), or interpreted.
- **Resource Exhaustion Safeguards**: A configurable maximum file size (default: 50 MB) prevents archive and memory exhaustion attacks.
- **Memory Safety**: Parsing is performed using pure-Python `pefile` and Python `cryptography`, preventing native C-extension memory crashes on malformed PE headers.
- **Malformed Input Resilience**: Any truncated headers, invalid magic numbers, or corrupted certificate directory offsets are caught gracefully and reported as structured errors without crashing the CLI or service.

---

## 3. PE File & Authenticode Structure

```
                  Windows PE Binary (.exe / .dll / .sys)
 ┌──────────────────────────────────────────────────────────────────────┐
 │ DOS Header (e_magic = 'MZ', e_lfanew -> PE Header Offset)            │
 ├──────────────────────────────────────────────────────────────────────┤
 │ PE Signature ('PE\0\0')                                              │
 ├──────────────────────────────────────────────────────────────────────┤
 │ COFF File Header (Machine: x86, x86-64, ARM64)                       │
 ├──────────────────────────────────────────────────────────────────────┤
 │ Optional Header (Magic: PE32 (0x10B) / PE32+ (0x20B))                │
 │  └── Data Directories[4]: IMAGE_DIRECTORY_ENTRY_SECURITY             │
 │        ├── VirtualAddress: File Offset to WIN_CERTIFICATE            │
 │        └── Size: Total Length of Security Entry                      │
 ├──────────────────────────────────────────────────────────────────────┤
 │ Section Headers & Raw Section Data (.text, .data, .rsrc)             │
 ├──────────────────────────────────────────────────────────────────────┤
 │ Authenticode WIN_CERTIFICATE Table                                   │
 │  ├── dwLength (4 bytes): Total length of certificate entry           │
 │  ├── wRevision (2 bytes): WIN_CERT_REVISION_2_0 (0x0200)             │
 │  ├── wCertificateType (2 bytes): WIN_CERT_TYPE_PKCS_SIGNED_DATA (2)  │
 │  └── bCertificate (N bytes): PKCS#7 / CMS SignedData ASN.1 Payload   │
 │        └── Embedded X.509 Certificate Chain                          │
 └──────────────────────────────────────────────────────────────────────┘
```

---

## 4. Discovery States

| Authenticode Status | Operational Meaning |
|---|---|
| `SIGNED` | Valid Authenticode security table detected with one or more extracted X.509 certificates. |
| `UNSIGNED` | PE headers are valid, but `IMAGE_DIRECTORY_ENTRY_SECURITY` is zero. Classified with `quantum_status: "NOT_APPLICABLE"` and `risk_score: 0.0`. |
| `SIGNATURE_PARSE_ERROR` | Authenticode entry is corrupted, out-of-bounds, or contains malformed PKCS#7 bytes. |

---

## 5. End-to-End Intelligence Pipeline Integration

When a PE artifact is scanned, it flows through SignChain's unified pipeline:

```
                  example.exe
                       │
                       ▼
                 PEScanner (can_handle -> scan -> normalize)
                       │
                       ▼
          Authenticode PKCS#7 Extraction
                       │
                       ▼
      Phase 3: CryptoClassifier (RSA-2048 -> VULNERABLE)
                       │
                       ▼
      Phase 4: QuantumRiskEngine (Calculates explainable risk score)
                       │
                       ▼
      Phase 5: DependencyGraph (Artifact -> Cert -> CA relations)
                       │
                       ▼
      Phase 6: PQCReadinessEngine (NOT_READY, ML-DSA candidates)
                       │
                       ▼
      Phase 7: MigrationPrioritizationEngine (Priority: P1 — CRITICAL)
```

---

## 6. Signature Verification Scope & Limitations

> [!NOTE]
> *Verification Limitation Notice*: SignChain extracts and analyzes the cryptographic algorithm parameters of embedded Authenticode certificates. SignChain does **not** recalculate PE Authenticode page hashes or validate complete Windows trust chain root anchors against the Windows Certificate Store.
> 
> When Authenticode signatures are detected, the status is reported transparently as:
> `signature_verification: "SIGNATURE_DETECTED_VERIFICATION_NOT_IMPLEMENTED"`.

---

## 7. CLI Usage

```powershell
# Scan Windows PE binary (automatically detected)
signchain scan target_app.exe

# Output structured JSON
signchain scan target_app.exe --json

# Run PQC readiness evaluation directly on PE
signchain pqc target_app.exe

# Generate dependency-aware migration roadmap
signchain migration target_app.exe
```

---

## 8. Research Significance

Supporting PE / Authenticode artifacts advances SignChain from theoretical certificate analysis to **concrete software supply chain artifact evaluation**. This enables empirical experiments comparing:
1. Discovery rate of vulnerable code-signing keys across executable binaries.
2. Downstream impact analysis of shared internal signing certificates across executable suites.
3. Post-quantum migration roadmap feasibility for compiled Windows software.
