# OpenPGP / PGP Signature Discovery & Cryptographic Analysis

## 1. Overview & Purpose
The `PGPScanner` plugin extends SignChain with static OpenPGP (RFC 4880, RFC 6637, RFC 9580) parsing capabilities. It identifies cryptographic signing keys, detached signatures, and cleartext signed messages across software supply chain artifacts (e.g., `.asc`, `.gpg`, `.pgp`, `.sig`) without executing external GPG binaries or importing keys into the host operating system keyring.

---

## 2. Security Architecture & Threat Model

### Pure Static Analysis
OpenPGP artifacts encountered in software supply chains are untrusted inputs. SignChain enforces strict static isolation:
- **No Keyring Alteration**: Does not invoke `gpg` CLI or modify `~/.gnupg/secring.gpg` / `pubring.kbx`.
- **Zero Decryption / Private Key Usage**: Secret key packets (Tags 5 & 7) are inspected strictly for public-key algorithm metadata and creation timestamps without reading or manipulating secret MPIs.
- **Resource Exhaustion Defense**: Implements a strict default 10 MB file size limit (`MAX_PGP_FILE_SIZE_BYTES`) and bounds packet length parsing to protect against recursive decompression and memory exhaustion attacks.

---

## 3. Supported Formats & Object Types

| Format / Extension | Input Type | Description |
|---|---|---|
| `.asc` | ASCII Armored Block | Radix-64 encoded block with CRC24 checksum (`BEGIN PGP PUBLIC KEY BLOCK`, `BEGIN PGP SIGNATURE`, `BEGIN PGP SIGNED MESSAGE`). |
| `.gpg`, `.pgp` | Binary Packet Stream | Raw RFC 4880 OpenPGP packet stream. |
| `.sig` | Detached Signature | Standalone binary or armored signature packet applied to an external artifact. |

### Detected Object Types
- `PUBLIC_KEY`: Transferable OpenPGP public key and subkey packets.
- `PRIVATE_KEY`: OpenPGP secret key packet (metadata parsed statically).
- `SIGNED_MESSAGE`: Cleartext signed document with embedded signature block.
- `DETACHED_SIGNATURE`: Standalone signature packet referencing an external file.
- `UNKNOWN_OPENPGP_OBJECT`: Unidentified valid OpenPGP packet sequence.
- `INVALID_OPENPGP_DATA`: Malformed, corrupted, or non-PGP payload.

---

## 4. Metadata Extraction Pipeline

```
  OpenPGP File (.asc / .gpg / .sig)
                 │
                 ▼
  ASCII Armor & Radix-64 Decoder
                 │ (Raw Packet Stream)
                 ▼
     RFC 4880 Packet Parser
                 │
     ┌───────────┴───────────┐
     ▼                       ▼
 Key Packets (Tag 6/14)  Signature Packets (Tag 2)
  - Key ID & Fingerprint   - Issuer Key ID
  - PubKey Algorithm       - Hash Algorithm (SHA-256, SHA-512)
  - Key Size / Curve       - Signature Type (Binary, Text)
  - User IDs (Tag 13)      - Creation / Expiration Times
  - Creation / Expiration  - Verification: NOT_PERFORMED
                 │
                 ▼
     SignChain Intelligence Pipeline
  (CryptoClassifier -> RiskEngine -> Graph -> PQC Readiness -> Migration)
```

---

## 5. Verification Capabilities & Limitations

> [!IMPORTANT]
> **Distinction Between Signature Detection and Cryptographic Verification**:
> SignChain identifies the presence, structure, and cryptographic algorithm parameters of OpenPGP signatures. It explicitly flags signatures as `signature_verification: "VERIFICATION_NOT_PERFORMED"` to indicate that detection does not equate to full web-of-trust validation.

---

## 6. Dependency Graph Integration

OpenPGP artifacts integrate into SignChain's unified `DependencyGraph`:
- **Nodes**:
  - `NodeType.ARTIFACT`: The signed document or binary.
  - `NodeType.PGP_KEY`: The signing key or public subkey identified by its 16-character Key ID and 40-character fingerprint.
  - `NodeType.SIGNER`: The human or organizational identity extracted from User ID packets (e.g., `Alice <alice@example.com>`).
- **Edges**:
  - `EdgeType.SIGNED_BY`: Connects `ARTIFACT` $\rightarrow$ `PGP_KEY`.
  - `EdgeType.BELONGS_TO`: Connects `PGP_KEY` $\rightarrow$ `SIGNER`.
