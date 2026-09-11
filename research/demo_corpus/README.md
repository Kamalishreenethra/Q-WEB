# Controlled Demonstration Corpus

> **CLASSIFICATION: CONTROLLED DEMONSTRATION CORPUS**  
> **PURPOSE: UI/UX & Pipeline Integration Verification Only**  
> **DISCLAIMER: These are synthetic, public self-signed test certificates generated strictly for demonstration and UI testing. They do NOT represent real-world compromised infrastructure, private keys, or Phase 15 research validation evidence.**

---

## 1. Overview & Generation Method
- **Generation Date:** 2026-08-16
- **Generation Tool:** Python `cryptography` library (`cryptography.x509`)
- **Key Safety Guarantee:** All private keys were generated Ephemerally in-memory and immediately discarded. Zero private key files are stored or tracked in this repository.
- **Corpus Size:** 12 self-contained public X.509 certificates (`.pem` format)
- **Supported Scanner Plugin:** `X509Scanner` (`src/signchain/scanners/x509_scanner.py`)
- **Ingestion Command:**
  ```powershell
  signchain store research/demo_corpus/certificates/<certificate_name>.pem
  ```

---

## 2. Cryptographic Diversity & Matrix
The corpus covers a diverse matrix of asymmetric algorithms, key parameters, validity horizons, and certificate hierarchy types:

| Certificate | Role | Algorithm | Key Size / Curve | CA Status |
|---|---|---|---|---|
| `demo_root_ca_rsa4096.pem` | Enterprise Root CA | RSA | 4096-bit | `CA:TRUE` |
| `demo_intermediate_ca_rsa3072.pem` | Intermediate Code Signing CA | RSA | 3072-bit | `CA:TRUE` |
| `demo_code_signing_rsa2048_a.pem` | Release Engineering Signer | RSA | 2048-bit | `CA:FALSE` |
| `demo_code_signing_rsa2048_b.pem` | CI/CD Pipeline Signer | RSA | 2048-bit | `CA:FALSE` |
| `demo_code_signing_rsa3072.pem` | Package Publisher | RSA | 3072-bit | `CA:FALSE` |
| `demo_code_signing_rsa4096.pem` | Kernel Driver Publisher | RSA | 4096-bit | `CA:FALSE` |
| `demo_root_ca_ecdsa_p384.pem` | Elliptic Root Authority | ECDSA | SECP384R1 (P-384) | `CA:TRUE` |
| `demo_code_signing_ecdsa_p256.pem` | Container Signer | ECDSA | SECP256R1 (P-256) | `CA:FALSE` |
| `demo_code_signing_ecdsa_p384.pem` | Microservice Attestation Key | ECDSA | SECP384R1 (P-384) | `CA:FALSE` |
| `demo_code_signing_ecdsa_p521.pem` | High-Assurance Signer | ECDSA | SECP521R1 (P-521) | `CA:FALSE` |
| `demo_code_signing_ed25519.pem` | Git Commit Signer | Ed25519 | Ed25519 (RFC 8032) | `CA:FALSE` |
| `demo_timestamping_rsa2048.pem` | Authenticode Timestamp Authority | RSA | 2048-bit | `CA:FALSE` |

---

## 3. Cryptographic Artifact Hashes
| Filename | Size (bytes) | SHA-256 Digest |
|---|---|---|
| `demo_code_signing_ecdsa_p256.pem` | 753 | `a07631936b7f9d43520fc47f3a22019a6cf5f86c0e75443cf3fedab1a9c616aa` |
| `demo_code_signing_ecdsa_p384.pem` | 891 | `ab4f7f4f3077267c9e5f161b3f098ece9a521a8a682e5b601d823a7b979a0eec` |
| `demo_code_signing_ecdsa_p521.pem` | 981 | `3451dd47d47c88ca9bfab738e5b863f1d99c2d389c33a7d02902bd46dcc117c3` |
| `demo_code_signing_ed25519.pem` | 709 | `46642a4ebd2f67ec66592c94d8c914b540645d364fc83036106f9b58f8203d11` |
| `demo_code_signing_rsa2048_a.pem` | 1318 | `99110a809459cc717dd5a5459eb30908c3f6eb83dffd73a24918501a044dada4` |
| `demo_code_signing_rsa2048_b.pem` | 1298 | `86508a0f74214ec826aec7b294b0c9195270c33038c260b32c7862b293c5873b` |
| `demo_code_signing_rsa3072.pem` | 1647 | `1cf39f3b29ded9a1f0cb004a4c44b78241f2a71499217dc15bb5086fd82e236d` |
| `demo_code_signing_rsa4096.pem` | 2004 | `91df1a375260ac555f3f005f5849f11b5ea2071048c37fe54be485cde5d688ef` |
| `demo_intermediate_ca_rsa3072.pem` | 1651 | `f916c9d3c788164df646c8be524f801c47c674bd1cb2ac5421eb72b0a5abbdba` |
| `demo_root_ca_ecdsa_p384.pem` | 855 | `bae0d2bf1601194557c9a7b8c52005a25c65817c72faab8c8eb1939a2b31cf15` |
| `demo_root_ca_rsa4096.pem` | 1988 | `0a849329ed75ab6106c1d175eb15cc8d0b523ca80c4d12555a1bef0dc43a176c` |
| `demo_timestamping_rsa2048.pem` | 1346 | `98c3b94ef7a8e4d220ea6ac318954f8b513a164ff6342cb4651916191ea90147` |

