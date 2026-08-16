"""
Sigstore Artifact and Signing Analysis Scanner plugin for SignChain.
Statically analyzes Sigstore bundles, DSSE envelopes, and Cosign JSON artifacts
extracting signing certificates, OIDC identities, Rekor transparency-log evidence,
and artifact digests in an offline-first architecture.
"""
import os
import json
import time
import base64
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa

from signchain.scanners.base import BaseScanner, extract_certificate_metadata, extract_public_key_details
from signchain.classifiers.crypto_classifier import CryptoClassifier
from signchain.risk.risk_engine import QuantumRiskEngine

MAX_SIGSTORE_FILE_SIZE_BYTES = 20 * 1024 * 1024  # 20 MB limit for static analysis safety
SUPPORTED_SIGSTORE_EXTENSIONS = {".sigstore.json", ".bundle", ".sigstore", ".dsse", ".intoto.jsonl"}

# Fulcio Custom OIDC Extension OIDs (OID arc 1.3.6.1.4.1.57264.1.*)
FULCIO_OID_ISSUER = "1.3.6.1.4.1.57264.1.1"
FULCIO_OID_GITHUB_TRIGGER = "1.3.6.1.4.1.57264.1.2"
FULCIO_OID_GITHUB_SHA = "1.3.6.1.4.1.57264.1.3"
FULCIO_OID_GITHUB_NAME = "1.3.6.1.4.1.57264.1.4"
FULCIO_OID_GITHUB_REPO = "1.3.6.1.4.1.57264.1.5"
FULCIO_OID_GITHUB_REF = "1.3.6.1.4.1.57264.1.6"


class SigstoreScanner(BaseScanner):
    """
    Scanner plugin for parsing Sigstore bundles, signing certificates, and transparency log metadata.
    Strictly operates offline by default without making live Rekor or Fulcio requests.
    """

    def __init__(self, max_file_size: int = MAX_SIGSTORE_FILE_SIZE_BYTES):
        self.max_file_size = max_file_size

    def can_handle(self, file_path: str) -> bool:
        """
        Determines if the given file is a Sigstore bundle or envelope based on extension or JSON keys.
        """
        if not file_path or not isinstance(file_path, str):
            return False

        if not os.path.isfile(file_path):
            return False

        lower_path = file_path.lower()
        for ext in SUPPORTED_SIGSTORE_EXTENSIONS:
            if lower_path.endswith(ext):
                return True

        if lower_path.endswith(".json"):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    preview = f.read(1024)
                    if any(marker in preview for marker in [
                        "application/vnd.dev.sigstore",
                        "verificationMaterial",
                        "rekorBundle",
                        "tlogEntries",
                        "dsseEnvelope",
                    ]):
                        return True
            except Exception:
                return False

        return False

    def scan(self, file_path: str, verify_online: bool = False) -> Dict[str, Any]:
        """
        Statically parses Sigstore metadata and extracts signing certificates, identities, and transparency log info.
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
            with open(file_path, "r", encoding="utf-8") as f:
                bundle_data = json.load(f)
        except Exception as e:
            return {
                "status": "ERROR",
                "error_message": f"Failed to parse JSON content: {str(e)}",
                "file_path": file_path,
            }

        if not isinstance(bundle_data, dict):
            return {
                "status": "ERROR",
                "error_message": "Root of Sigstore bundle must be a JSON object.",
                "file_path": file_path,
            }

        media_type = bundle_data.get("mediaType", "application/vnd.dev.sigstore.bundle+json;version=UNKNOWN")

        # 1. Extract Artifact Digest
        artifact_digest = self._extract_artifact_digest(bundle_data)

        # 2. Extract Certificates
        raw_certs = self._extract_raw_certificates(bundle_data)
        parsed_certs: List[Dict[str, Any]] = []
        signing_identity: Dict[str, Any] = {
            "value": "UNKNOWN",
            "type": "UNKNOWN",
            "issuer": "UNKNOWN",
            "status": "UNKNOWN",
            "claims": {},
        }

        for idx, cert_bytes in enumerate(raw_certs):
            try:
                cert_obj = x509.load_der_x509_certificate(cert_bytes)
            except Exception:
                try:
                    cert_obj = x509.load_pem_x509_certificate(cert_bytes)
                except Exception:
                    continue

            identity_info = self._extract_fulcio_identity(cert_obj)
            if idx == 0 and identity_info.get("value") != "UNKNOWN":
                signing_identity = identity_info

            rec = extract_certificate_metadata(
                cert=cert_obj,
                file_path=file_path,
                format_label="Sigstore (X.509)",
                index=idx,
                extra_fields={
                    "sigstore_identity": identity_info.get("value"),
                    "sigstore_identity_type": identity_info.get("type"),
                    "sigstore_oidc_issuer": identity_info.get("issuer"),
                },
            )
            parsed_certs.append(rec)

        # 3. Extract Transparency Log (Rekor) Evidence
        tlog_info = self._extract_transparency_evidence(bundle_data)

        # 4. Extract Signature Metadata
        sig_info = self._extract_signature_info(bundle_data)

        # 5. Determine Overall Classification & Risk
        primary_cert = parsed_certs[0] if parsed_certs else None
        canonical_alg = primary_cert.get("canonical_algorithm", "UNKNOWN") if primary_cert else "UNKNOWN"
        quantum_status = primary_cert.get("quantum_status", "UNKNOWN") if primary_cert else "UNKNOWN"
        risk_score = primary_cert.get("risk_score", 50.0) if primary_cert else 50.0
        risk_level = primary_cert.get("risk_level", "MEDIUM") if primary_cert else "MEDIUM"

        scan_time = time.perf_counter() - t_start

        return {
            "status": "SUCCESS",
            "artifact_name": os.path.basename(file_path),
            "file_path": file_path,
            "file_size": file_size,
            "ecosystem": "SIGSTORE",
            "media_type": media_type,
            "artifact": {
                "digest": artifact_digest,
            },
            "signing": {
                "ecosystem": "SIGSTORE",
                "signature_status": "SIGNATURE_PRESENT" if sig_info.get("present") else "SIGNATURE_MISSING",
                "signature_algorithm": sig_info.get("algorithm", canonical_alg),
                "verification_status": "NOT_PERFORMED",
            },
            "certificate": primary_cert,
            "certificates": parsed_certs,
            "identity": signing_identity,
            "transparency": tlog_info,
            "quantum_status": quantum_status,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "scan_time_sec": round(scan_time, 6),
        }

    def normalize_result(self, raw_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Normalizes raw scanner output into standard SignChain output format.
        """
        if raw_result.get("status") != "SUCCESS":
            return [{
                "status": "ERROR",
                "file_path": raw_result.get("file_path", "unknown"),
                "error_message": raw_result.get("error_message", "Unknown error during Sigstore scan"),
            }]

        certs = raw_result.get("certificates", [])
        if not certs:
            return [{
                "status": "SUCCESS",
                "artifact_name": raw_result.get("artifact_name"),
                "file_path": raw_result.get("file_path"),
                "format": "Sigstore (Bundle)",
                "ecosystem": "SIGSTORE",
                "quantum_status": "UNKNOWN",
                "risk_score": 50.0,
                "risk_level": "MEDIUM",
                "public_key_algorithm": "UNKNOWN",
                "canonical_algorithm": "UNKNOWN",
                "signing_identity": raw_result.get("identity", {}).get("value", "UNKNOWN"),
            }]

        return certs

    def _extract_artifact_digest(self, data: Dict[str, Any]) -> Dict[str, str]:
        """Extracts artifact digest algorithm and hash value from bundle payload."""
        # Check standard Sigstore bundle messageSignature
        msg_sig = data.get("messageSignature", {})
        if msg_sig and "messageDigest" in msg_sig:
            digest_obj = msg_sig["messageDigest"]
            alg = digest_obj.get("algorithm", "SHA2_256").replace("SHA2_", "SHA-")
            raw_val = digest_obj.get("digest", "")
            try:
                hex_val = base64.b64decode(raw_val).hex().lower()
            except Exception:
                hex_val = raw_val
            return {"algorithm": alg, "value": hex_val}

        # Check DSSE envelope payload
        dsse = data.get("dsseEnvelope", {})
        if dsse and "payload" in dsse:
            try:
                payload_bytes = base64.b64decode(dsse["payload"])
                payload_json = json.loads(payload_bytes.decode("utf-8"))
                subjects = payload_json.get("subject", [])
                if subjects and "digest" in subjects[0]:
                    d = subjects[0]["digest"]
                    for alg_key, hash_val in d.items():
                        return {"algorithm": alg_key.upper(), "value": hash_val}
            except Exception:
                pass

        return {"algorithm": "UNKNOWN", "value": "UNKNOWN"}

    def _extract_raw_certificates(self, data: Dict[str, Any]) -> List[bytes]:
        """Extracts raw certificate bytes (DER or PEM) from bundle verificationMaterial or Cosign fields."""
        certs = []
        vm = data.get("verificationMaterial", {})

        # Standard Sigstore v0.3 x509CertificateChain
        cert_chain = vm.get("x509CertificateChain", {}).get("certificates", [])
        for c in cert_chain:
            if "rawBytes" in c:
                try:
                    certs.append(base64.b64decode(c["rawBytes"]))
                except Exception:
                    pass

        # Standard Sigstore v0.1/v0.2 certificate
        if not certs and "certificate" in vm:
            cert_obj = vm["certificate"]
            if "rawBytes" in cert_obj:
                try:
                    certs.append(base64.b64decode(cert_obj["rawBytes"]))
                except Exception:
                    pass

        # Cosign / legacy JSON certificate field
        if not certs and "certificate" in data:
            cert_val = data["certificate"]
            if isinstance(cert_val, str):
                certs.append(cert_val.encode("utf-8"))

        return certs

    def _extract_fulcio_identity(self, cert: x509.Certificate) -> Dict[str, Any]:
        """Extracts SAN Email/URI and Fulcio custom OIDC claims from certificate extensions."""
        identity_val = "UNKNOWN"
        identity_type = "UNKNOWN"
        oidc_issuer = "UNKNOWN"
        claims = {}

        # 1. Subject Alternative Names (SAN)
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                if isinstance(name, x509.RFC822Name):
                    identity_val = name.value
                    identity_type = "EMAIL"
                    break
                elif isinstance(name, x509.UniformResourceIdentifier):
                    identity_val = name.value
                    identity_type = "URI"
                    break
        except x509.ExtensionNotFound:
            pass

        # Fallback to Subject DN Common Name if SAN missing
        if identity_val == "UNKNOWN":
            for attr in cert.subject:
                if attr.oid == x509.oid.NameOID.COMMON_NAME:
                    identity_val = attr.value
                    identity_type = "COMMON_NAME"
                    break

        # 2. Extract Fulcio OIDC Extensions
        for ext in cert.extensions:
            oid_str = ext.oid.dotted_string
            if oid_str == FULCIO_OID_ISSUER:
                oidc_issuer = ext.value.value.decode("utf-8", errors="replace") if hasattr(ext.value, "value") else str(ext.value)
            elif oid_str == FULCIO_OID_GITHUB_REPO:
                claims["github_repo"] = ext.value.value.decode("utf-8", errors="replace") if hasattr(ext.value, "value") else str(ext.value)
            elif oid_str == FULCIO_OID_GITHUB_REF:
                claims["github_ref"] = ext.value.value.decode("utf-8", errors="replace") if hasattr(ext.value, "value") else str(ext.value)
            elif oid_str == FULCIO_OID_GITHUB_SHA:
                claims["github_sha"] = ext.value.value.decode("utf-8", errors="replace") if hasattr(ext.value, "value") else str(ext.value)

        return {
            "value": identity_val,
            "type": identity_type,
            "issuer": oidc_issuer,
            "status": "OBSERVED",
            "claims": claims,
        }

    def _extract_transparency_evidence(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extracts Rekor transparency log entries, log index, integrated time, and inclusion proof."""
        vm = data.get("verificationMaterial", {})
        tlog_entries = vm.get("tlogEntries", [])

        if not tlog_entries and "rekorBundle" in data:
            rekor_entry = data["rekorBundle"]
            tlog_entries = [rekor_entry]

        if not tlog_entries:
            return {
                "status": "MISSING",
                "verification": "NOT_VERIFIED",
                "entries_count": 0,
                "entries": [],
            }

        parsed_entries = []
        for e in tlog_entries:
            log_idx = e.get("logIndex", "UNKNOWN")
            int_time_raw = e.get("integratedTime")
            int_time_iso = "UNKNOWN"
            if int_time_raw:
                try:
                    int_time_iso = datetime.fromtimestamp(int(int_time_raw), tz=timezone.utc).isoformat()
                except Exception:
                    pass

            proof = e.get("inclusionProof", {})
            tree_size = proof.get("treeSize", "UNKNOWN")
            root_hash_raw = proof.get("rootHash", "")
            try:
                root_hash_hex = base64.b64decode(root_hash_raw).hex().lower() if root_hash_raw else "UNKNOWN"
            except Exception:
                root_hash_hex = root_hash_raw or "UNKNOWN"

            parsed_entries.append({
                "log_index": str(log_idx),
                "integrated_time": int_time_iso,
                "tree_size": str(tree_size),
                "root_hash": root_hash_hex,
                "evidence_status": "PRESENT",
            })

        return {
            "status": "PRESENT",
            "verification": "NOT_VERIFIED",
            "entries_count": len(parsed_entries),
            "entries": parsed_entries,
        }

    def _extract_signature_info(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extracts signature presence and structure."""
        if "messageSignature" in data:
            return {
                "present": True,
                "type": "MESSAGE_SIGNATURE",
                "algorithm": "UNKNOWN",
            }
        elif "dsseEnvelope" in data:
            sigs = data["dsseEnvelope"].get("signatures", [])
            return {
                "present": len(sigs) > 0,
                "type": "DSSE_ENVELOPE",
                "count": len(sigs),
            }
        elif "signature" in data:
            return {
                "present": True,
                "type": "COSIGN_SIGNATURE",
            }
        return {"present": False, "type": "NONE"}
