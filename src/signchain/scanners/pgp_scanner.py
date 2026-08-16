"""
OpenPGP / PGP Signature Scanner plugin for SignChain.
Statically parses OpenPGP keys, signed messages, and detached signatures (.asc, .gpg, .pgp, .sig)
without executing GPG binaries or importing keys into the host keyring.
"""
import os
import re
import time
import struct
import base64
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from signchain.scanners.base import BaseScanner
from signchain.classifiers.crypto_classifier import CryptoClassifier
from signchain.risk.risk_engine import QuantumRiskEngine

MAX_PGP_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB limit for static analysis safety
SUPPORTED_PGP_EXTENSIONS = {".asc", ".gpg", ".pgp", ".sig"}

# RFC 4880 Public Key Algorithms
PGP_PUBKEY_ALGORITHMS = {
    1: ("RSA", "RSA (Encrypt or Sign)"),
    2: ("RSA", "RSA (Encrypt-Only)"),
    3: ("RSA", "RSA (Sign-Only)"),
    16: ("Elgamal", "Elgamal (Encrypt-Only)"),
    17: ("DSA", "DSA (Digital Signature Algorithm)"),
    18: ("ECDH", "ECDH (Elliptic Curve Diffie-Hellman)"),
    19: ("ECDSA", "ECDSA (Elliptic Curve Digital Signature Algorithm)"),
    22: ("EdDSA", "EdDSA (Edwards-curve Digital Signature Algorithm)"),
}

# RFC 4880 Hash Algorithms
PGP_HASH_ALGORITHMS = {
    1: "MD5",
    2: "SHA-1",
    3: "RIPEMD160",
    8: "SHA-256",
    9: "SHA-384",
    10: "SHA-512",
    11: "SHA-224",
    12: "SHA3-256",
    14: "SHA3-512",
}

# RFC 4880 Signature Types
PGP_SIGNATURE_TYPES = {
    0x00: "BINARY_DOCUMENT",
    0x01: "CANONICAL_TEXT",
    0x02: "STANDALONE",
    0x10: "GENERIC_CERTIFICATION",
    0x11: "PERSONA_CERTIFICATION",
    0x12: "CASUAL_CERTIFICATION",
    0x13: "POSITIVE_CERTIFICATION",
    0x18: "SUBKEY_BINDING",
    0x19: "PRIMARY_KEY_BINDING",
    0x20: "KEY_REVOCATION",
    0x28: "SUBKEY_REVOCATION",
    0x30: "CERTIFICATION_REVOCATION",
}

# Well-known ECC Curve OIDs in OpenPGP (RFC 6637 / RFC 9580)
PGP_ECC_CURVE_OIDS = {
    b"\x2a\x86\x48\xce\x3d\x03\x01\x07": ("NIST P-256", 256, "1.2.840.10045.3.1.7"),
    b"\x2b\x81\x04\x00\x22": ("NIST P-384", 384, "1.3.132.0.34"),
    b"\x2b\x81\x04\x00\x23": ("NIST P-521", 521, "1.3.132.0.35"),
    b"\x2b\x81\x04\x00\x0a": ("secp256k1", 256, "1.3.132.0.10"),
    b"\x2b\x06\x01\x04\x01\xda\x47\x0f\x01": ("Ed25519", 256, "1.3.6.1.4.1.11591.15.1"),
    b"\x2b\x06\x01\x04\x01\xda\x47\x0f\x02": ("X25519", 256, "1.3.6.1.4.1.11591.15.2"),
    b"\x2b\x06\x01\x04\x01\xda\x47\x0f\x03": ("Ed448", 448, "1.3.6.1.4.1.11591.15.3"),
}


class PGPScanner(BaseScanner):
    """
    Scanner plugin for parsing and extracting metadata from OpenPGP artifacts.
    Strictly performs safe static analysis without invoking GPG binaries or keyrings.
    """

    def __init__(self, max_file_size: int = MAX_PGP_FILE_SIZE_BYTES):
        self.max_file_size = max_file_size

    def can_handle(self, file_path: str) -> bool:
        """
        Determines whether this scanner can handle the file based on extension or ASCII armor header.
        """
        if not file_path or not isinstance(file_path, str):
            return False

        if not os.path.isfile(file_path):
            return False

        ext = os.path.splitext(file_path)[1].lower()
        if ext in SUPPORTED_PGP_EXTENSIONS:
            return True

        # Check for OpenPGP ASCII Armor headers
        try:
            with open(file_path, "rb") as f:
                header = f.read(512)
                if b"-----BEGIN PGP " in header:
                    return True
                # Check binary OpenPGP packet tag (high bit must be 1)
                if len(header) >= 2 and (header[0] & 0x80) != 0:
                    tag = (header[0] & 0x3F) if (header[0] & 0x40) != 0 else ((header[0] >> 2) & 0x0F)
                    if tag in (1, 2, 4, 5, 6, 7, 13, 14):
                        return True
        except Exception:
            return False

        return False

    def scan(self, file_path: str) -> Dict[str, Any]:
        """
        Statically parses an OpenPGP artifact and extracts key, signature, and algorithm metadata.
        """
        t_start = time.perf_counter()

        if not os.path.exists(file_path):
            return {
                "status": "ERROR",
                "error_message": f"File does not exist: {file_path}",
                "file_path": file_path,
            }

        if not os.path.isfile(file_path):
            return {
                "status": "ERROR",
                "error_message": f"Path is not a regular file: {file_path}",
                "file_path": file_path,
            }

        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return {
                "status": "ERROR",
                "error_message": "File is empty (0 bytes).",
                "file_path": file_path,
            }

        if file_size > self.max_file_size:
            return {
                "status": "ERROR",
                "error_message": f"File exceeds maximum allowed size ({file_size} > {self.max_file_size} bytes).",
                "file_path": file_path,
            }

        try:
            with open(file_path, "rb") as f:
                raw_bytes = f.read()
        except Exception as e:
            return {
                "status": "ERROR",
                "error_message": f"Failed to read file: {str(e)}",
                "file_path": file_path,
            }

        # 1. Detect ASCII Armor vs Binary Stream
        object_type, binary_payload = self._parse_armor_or_binary(raw_bytes)
        if object_type == "INVALID_OPENPGP_DATA":
            return {
                "status": "ERROR",
                "error_message": "Invalid or unparseable OpenPGP data.",
                "file_path": file_path,
                "object_type": object_type,
            }

        # 2. Parse OpenPGP Packet Stream
        packets = self._parse_packets(binary_payload)
        if not packets:
            return {
                "status": "ERROR",
                "error_message": "No valid OpenPGP packets found in payload.",
                "file_path": file_path,
                "object_type": object_type,
            }

        # 3. Extract Keys, Subkeys, Signatures, and User IDs
        keys_list = []
        sigs_list = []
        current_key: Optional[Dict[str, Any]] = None

        for tag, body in packets:
            if tag in (6, 14, 5, 7):  # Public Key, Public Subkey, Secret Key, Secret Subkey
                is_subkey = tag in (14, 7)
                is_secret = tag in (5, 7)
                key_meta = self._parse_key_packet(body, is_subkey=is_subkey, is_secret=is_secret, file_path=file_path)
                if key_meta:
                    keys_list.append(key_meta)
                    if not is_subkey:
                        current_key = key_meta
            elif tag == 13:  # User ID Packet
                uid_str = body.decode("utf-8", errors="replace").strip()
                if current_key is not None:
                    current_key.setdefault("user_ids", []).append(uid_str)
                    current_key["subject"] = uid_str
            elif tag == 2:  # Signature Packet
                sig_meta = self._parse_signature_packet(body, file_path=file_path)
                if sig_meta:
                    sigs_list.append(sig_meta)

        # 4. Refine Object Type if UNKNOWN
        if object_type == "UNKNOWN_OPENPGP_OBJECT":
            if sigs_list and not keys_list:
                object_type = "DETACHED_SIGNATURE"
            elif keys_list and not sigs_list:
                object_type = "PUBLIC_KEY" if not any(k.get("is_secret") for k in keys_list) else "PRIVATE_KEY"
            elif keys_list and sigs_list:
                object_type = "SIGNED_KEY_OR_BUNDLE"

        scan_time = time.perf_counter() - t_start

        return {
            "status": "SUCCESS",
            "artifact_name": os.path.basename(file_path),
            "file_path": file_path,
            "file_size": file_size,
            "object_type": object_type,
            "key_count": len(keys_list),
            "signature_count": len(sigs_list),
            "keys": keys_list,
            "signatures": sigs_list,
            "certificates": keys_list if keys_list else sigs_list,  # Normalize for pipeline consumers
            "scan_time_sec": round(scan_time, 6),
        }

    def normalize_result(self, raw_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Normalizes raw PGP scan output into standardized SignChain schema items.
        """
        if raw_result.get("status") != "SUCCESS":
            return [{
                "status": "ERROR",
                "file_path": raw_result.get("file_path", "unknown"),
                "error_message": raw_result.get("error_message", "Unknown error during OpenPGP scan"),
                "object_type": raw_result.get("object_type", "INVALID_OPENPGP_DATA"),
            }]

        items = []
        for k in raw_result.get("keys", []):
            items.append(k)
        for s in raw_result.get("signatures", []):
            items.append(s)

        if not items:
            return [{
                "status": "SUCCESS",
                "artifact_name": raw_result.get("artifact_name"),
                "file_path": raw_result.get("file_path"),
                "format": "OpenPGP",
                "object_type": raw_result.get("object_type"),
                "quantum_status": "NOT_APPLICABLE",
                "risk_score": 0.0,
                "risk_level": "LOW",
                "public_key_algorithm": "NONE",
                "canonical_algorithm": "NONE",
            }]

        return items

    def _parse_armor_or_binary(self, data: bytes) -> Tuple[str, bytes]:
        """Detects ASCII Armor blocks and extracts raw binary OpenPGP packet bytes."""
        text_preview = data[:1024].decode("latin-1", errors="replace")

        if "-----BEGIN PGP PUBLIC KEY BLOCK-----" in text_preview:
            return "PUBLIC_KEY", self._decode_armor(data, "-----BEGIN PGP PUBLIC KEY BLOCK-----", "-----END PGP PUBLIC KEY BLOCK-----")
        elif "-----BEGIN PGP PRIVATE KEY BLOCK-----" in text_preview:
            return "PRIVATE_KEY", self._decode_armor(data, "-----BEGIN PGP PRIVATE KEY BLOCK-----", "-----END PGP PRIVATE KEY BLOCK-----")
        elif "-----BEGIN PGP SIGNED MESSAGE-----" in text_preview:
            # Cleartext signed message: signature packet is between BEGIN PGP SIGNATURE and END PGP SIGNATURE
            return "SIGNED_MESSAGE", self._decode_armor(data, "-----BEGIN PGP SIGNATURE-----", "-----END PGP SIGNATURE-----")
        elif "-----BEGIN PGP SIGNATURE-----" in text_preview:
            return "DETACHED_SIGNATURE", self._decode_armor(data, "-----BEGIN PGP SIGNATURE-----", "-----END PGP SIGNATURE-----")
        elif "-----BEGIN PGP MESSAGE-----" in text_preview:
            return "ENCRYPTED_OR_ARMORED_MESSAGE", self._decode_armor(data, "-----BEGIN PGP MESSAGE-----", "-----END PGP MESSAGE-----")

        # Binary packet stream
        if len(data) >= 1 and (data[0] & 0x80) != 0:
            return "UNKNOWN_OPENPGP_OBJECT", data

        return "INVALID_OPENPGP_DATA", b""

    def _decode_armor(self, data: bytes, begin_marker: str, end_marker: str) -> bytes:
        """Extracts Base64 payload from ASCII armor and decodes to raw packet bytes."""
        try:
            text = data.decode("utf-8", errors="replace")
            start = text.find(begin_marker)
            end = text.find(end_marker)
            if start == -1 or end == -1:
                return b""

            block = text[start + len(begin_marker) : end]
            # Strip headers (e.g. Version: ..., Comment: ..., Hash: ...)
            lines = [l.strip() for l in block.splitlines() if l.strip()]
            b64_lines = []
            in_body = False
            for line in lines:
                if not in_body:
                    if ":" not in line and not line.startswith("-----"):
                        in_body = True
                if in_body:
                    if line.startswith("="):  # CRC24 checksum
                        continue
                    b64_lines.append(line)

            b64_str = "".join(b64_lines)
            return base64.b64decode(b64_str)
        except Exception:
            return b""

    def _parse_packets(self, data: bytes) -> List[Tuple[int, bytes]]:
        """Parses raw binary RFC 4880 OpenPGP packet stream."""
        packets = []
        offset = 0
        while offset < len(data):
            tag_byte = data[offset]
            if (tag_byte & 0x80) == 0:
                break
            offset += 1

            if (tag_byte & 0x40) != 0:
                # New packet format
                tag = tag_byte & 0x3F
                if offset >= len(data):
                    break
                l1 = data[offset]
                offset += 1
                if l1 < 192:
                    pkt_len = l1
                elif l1 < 224:
                    if offset >= len(data):
                        break
                    l2 = data[offset]
                    offset += 1
                    pkt_len = ((l1 - 192) << 8) + l2 + 192
                elif l1 == 255:
                    if offset + 4 > len(data):
                        break
                    pkt_len = struct.unpack(">I", data[offset : offset + 4])[0]
                    offset += 4
                else:
                    break
            else:
                # Old packet format
                tag = (tag_byte >> 2) & 0x0F
                ltype = tag_byte & 0x03
                if ltype == 0:
                    if offset >= len(data):
                        break
                    pkt_len = data[offset]
                    offset += 1
                elif ltype == 1:
                    if offset + 2 > len(data):
                        break
                    pkt_len = struct.unpack(">H", data[offset : offset + 2])[0]
                    offset += 2
                elif ltype == 2:
                    if offset + 4 > len(data):
                        break
                    pkt_len = struct.unpack(">I", data[offset : offset + 4])[0]
                    offset += 4
                else:
                    pkt_len = len(data) - offset

            body = data[offset : offset + pkt_len]
            offset += pkt_len
            packets.append((tag, body))

        return packets

    def _parse_key_packet(
        self,
        body: bytes,
        is_subkey: bool,
        is_secret: bool,
        file_path: str,
    ) -> Optional[Dict[str, Any]]:
        """Extracts cryptographic parameters, fingerprint, and quantum status from a Key Packet."""
        if len(body) < 6:
            return None

        version = body[0]
        if version not in (4, 3, 5):
            return None

        ctime = struct.unpack(">I", body[1:5])[0]
        ctime_iso = datetime.fromtimestamp(ctime, tz=timezone.utc).isoformat()

        alg_id = body[5]
        alg_name, alg_desc = PGP_PUBKEY_ALGORITHMS.get(alg_id, ("UNKNOWN", f"Unknown Algorithm ({alg_id})"))

        key_size: Optional[int] = None
        curve_name: Optional[str] = None
        oid_str: Optional[str] = None

        if alg_id in (1, 2, 3):  # RSA
            bit_len, _, _ = self._parse_mpi(body, 6)
            key_size = bit_len
        elif alg_id == 17:  # DSA
            bit_len, _, _ = self._parse_mpi(body, 6)
            key_size = bit_len
        elif alg_id in (18, 19, 22):  # ECDH, ECDSA, EdDSA
            if len(body) > 6:
                oid_len = body[6]
                oid_bytes = body[7 : 7 + oid_len]
                if oid_bytes in PGP_ECC_CURVE_OIDS:
                    curve_name, key_size, oid_str = PGP_ECC_CURVE_OIDS[oid_bytes]
                else:
                    curve_name = f"Unknown-Curve-{oid_bytes.hex()}"
                    key_size = 256

        # Calculate v4 Fingerprint: SHA-1 of 0x99 || 2-byte length || body
        fp_data = b"\x99" + struct.pack(">H", len(body)) + body
        sha1_fp = hashlib.sha1(fp_data).hexdigest().upper()
        key_id = sha1_fp[-16:]

        # SHA-256 Fingerprint for SignChain cross-artifact tracking
        sha256_fp = hashlib.sha256(fp_data).hexdigest().lower()

        # Deterministic Cryptographic Classification & Quantum Risk Evaluation
        classifier = CryptoClassifier()
        classification = classifier.classify(
            algorithm_name=alg_name,
            key_size=key_size,
            curve=curve_name,
            oid=oid_str,
            signature_algorithm=alg_name,
        )

        risk_engine = QuantumRiskEngine()
        crypto_risk_score = QuantumRiskEngine.map_crypto_risk_score(
            quantum_status=classification["quantum_status"],
            canonical_algorithm=classification["algorithm"],
        )
        risk_assessment = risk_engine.evaluate_risk(
            cryptographic_risk=crypto_risk_score,
            asset_criticality=50.0,
            exposure=50.0,
            validity_horizon=50.0,
            dependency_impact=50.0,
            migration_complexity=50.0,
        )

        return {
            "status": "SUCCESS",
            "artifact_name": os.path.basename(file_path),
            "file_path": file_path,
            "format": "OpenPGP (Key)",
            "key_type": "SUBKEY" if is_subkey else "PRIMARY_KEY",
            "is_secret": is_secret,
            "key_id": key_id,
            "fingerprint": sha1_fp,
            "sha256_fingerprint": sha256_fp,
            "serial_number": key_id,
            "subject": f"PGP Key [{key_id}]",
            "issuer": f"PGP Key [{key_id}]",
            "user_ids": [],
            "not_before": ctime_iso,
            "not_after": "UNKNOWN",
            "public_key_algorithm": alg_name,
            "canonical_algorithm": classification["algorithm"],
            "algorithm_family": classification["family"],
            "classical_security_bits": classification["key_parameters"]["security_bits"],
            "quantum_status": classification["quantum_status"],
            "quantum_reason": classification["reason"],
            "confidence_source": "Deterministic OpenPGP RFC 4880 Packet Parsing",
            "risk_score": risk_assessment["risk_score"],
            "risk_level": risk_assessment["risk_level"],
            "risk_breakdown": risk_assessment["contributions"],
            "risk_explanation": risk_assessment["explanation"],
            "risk_disclaimer": risk_assessment["disclaimer"],
            "key_size": key_size,
            "curve": curve_name,
            "is_ca": not is_subkey,
        }

    def _parse_signature_packet(self, body: bytes, file_path: str) -> Optional[Dict[str, Any]]:
        """Extracts signature type, issuer key ID, hash algorithm, and creation time from a Signature Packet."""
        if len(body) < 6:
            return None

        version = body[0]
        if version != 4:
            return None

        sig_type_code = body[1]
        sig_type_name = PGP_SIGNATURE_TYPES.get(sig_type_code, f"TYPE_{hex(sig_type_code)}")
        pk_alg_id = body[2]
        pk_alg_name, _ = PGP_PUBKEY_ALGORITHMS.get(pk_alg_id, ("UNKNOWN", "Unknown Algorithm"))
        hash_alg_id = body[3]
        hash_alg_name = PGP_HASH_ALGORITHMS.get(hash_alg_id, f"HASH_{hash_alg_id}")

        # Hashed subpackets
        hashed_len = struct.unpack(">H", body[4:6])[0]
        hashed_subpkts = body[6 : 6 + hashed_len]

        issuer_key_id = "UNKNOWN"
        sig_creation_time = "UNKNOWN"
        sig_expiration_time = None
        key_expiration_time = None

        subpkts = self._parse_subpackets(hashed_subpkts)
        # Also parse unhashed subpackets
        unhashed_offset = 6 + hashed_len
        if unhashed_offset + 2 <= len(body):
            unhashed_len = struct.unpack(">H", body[unhashed_offset : unhashed_offset + 2])[0]
            unhashed_subpkts = body[unhashed_offset + 2 : unhashed_offset + 2 + unhashed_len]
            subpkts.extend(self._parse_subpackets(unhashed_subpkts))

        for sub_tag, sub_body in subpkts:
            if sub_tag == 2 and len(sub_body) >= 4:  # Signature Creation Time
                ts = struct.unpack(">I", sub_body[:4])[0]
                sig_creation_time = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
            elif sub_tag == 3 and len(sub_body) >= 4:  # Signature Expiration Time
                ts = struct.unpack(">I", sub_body[:4])[0]
                sig_expiration_time = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
            elif sub_tag == 9 and len(sub_body) >= 4:  # Key Expiration Time
                ts = struct.unpack(">I", sub_body[:4])[0]
                key_expiration_time = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
            elif sub_tag == 16 and len(sub_body) >= 8:  # Issuer Key ID
                issuer_key_id = sub_body[:8].hex().upper()

        # Deterministic Cryptographic Classification for the signing key algorithm
        classifier = CryptoClassifier()
        classification = classifier.classify(
            algorithm_name=pk_alg_name,
            key_size=2048 if pk_alg_name == "RSA" else (256 if "EC" in pk_alg_name or "ED" in pk_alg_name else None),
            curve=None,
            oid=None,
            signature_algorithm=f"{pk_alg_name}+{hash_alg_name}",
        )

        risk_engine = QuantumRiskEngine()
        crypto_risk_score = QuantumRiskEngine.map_crypto_risk_score(
            quantum_status=classification["quantum_status"],
            canonical_algorithm=classification["algorithm"],
        )
        risk_assessment = risk_engine.evaluate_risk(
            cryptographic_risk=crypto_risk_score,
            asset_criticality=50.0,
            exposure=50.0,
            validity_horizon=50.0,
            dependency_impact=50.0,
            migration_complexity=50.0,
        )

        # Signature Fingerprint / Identifier
        sig_id = f"sig:{hashlib.sha256(body).hexdigest()[:16]}"

        return {
            "status": "SUCCESS",
            "artifact_name": os.path.basename(file_path),
            "file_path": file_path,
            "format": "OpenPGP (Signature)",
            "signature_type": sig_type_name,
            "signature_id": sig_id,
            "serial_number": issuer_key_id,
            "issuer_key_id": issuer_key_id,
            "issuer": f"PGP Key [{issuer_key_id}]",
            "subject": f"Signature on {os.path.basename(file_path)}",
            "sha256_fingerprint": hashlib.sha256(body).hexdigest().lower(),
            "hash_algorithm": hash_alg_name,
            "public_key_algorithm": pk_alg_name,
            "canonical_algorithm": classification["algorithm"],
            "algorithm_family": classification["family"],
            "classical_security_bits": classification["key_parameters"]["security_bits"],
            "quantum_status": classification["quantum_status"],
            "quantum_reason": classification["reason"],
            "confidence_source": "Deterministic OpenPGP RFC 4880 Signature Parsing",
            "signature_verification": "VERIFICATION_NOT_PERFORMED",
            "signature_creation_time": sig_creation_time,
            "not_before": sig_creation_time,
            "not_after": sig_expiration_time or "NEVER",
            "risk_score": risk_assessment["risk_score"],
            "risk_level": risk_assessment["risk_level"],
            "risk_breakdown": risk_assessment["contributions"],
            "risk_explanation": risk_assessment["explanation"],
            "risk_disclaimer": risk_assessment["disclaimer"],
            "is_ca": False,
        }

    def _parse_subpackets(self, data: bytes) -> List[Tuple[int, bytes]]:
        """Parses RFC 4880 subpacket structures from hashed or unhashed subpacket areas."""
        subpackets = []
        offset = 0
        while offset < len(data):
            if offset >= len(data):
                break
            l1 = data[offset]
            offset += 1
            if l1 < 192:
                sub_len = l1
            elif l1 < 255:
                if offset >= len(data):
                    break
                l2 = data[offset]
                offset += 1
                sub_len = ((l1 - 192) << 8) + l2 + 192
            elif l1 == 255:
                if offset + 4 > len(data):
                    break
                sub_len = struct.unpack(">I", data[offset : offset + 4])[0]
                offset += 4
            else:
                break

            if sub_len < 1 or offset >= len(data):
                break

            sub_tag = data[offset] & 0x7F  # Strip critical bit
            sub_body = data[offset + 1 : offset + sub_len]
            offset += sub_len
            subpackets.append((sub_tag, sub_body))

        return subpackets

    @staticmethod
    def _parse_mpi(data: bytes, offset: int) -> Tuple[int, bytes, int]:
        """Parses a Big-Endian Multi-Precision Integer (MPI)."""
        if offset + 2 > len(data):
            return 0, b"", offset
        bit_len = struct.unpack(">H", data[offset : offset + 2])[0]
        byte_len = (bit_len + 7) // 8
        offset += 2
        val_bytes = data[offset : offset + byte_len]
        offset += byte_len
        return bit_len, val_bytes, offset
