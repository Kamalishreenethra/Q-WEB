"""
OCI Container Image Signature Scanner plugin for SignChain.
Statically analyzes OCI and Docker image manifests, Cosign signature layers,
and Notary metadata in an offline-first architecture without executing container images.
"""
import os
import json
import time
import base64
import hashlib
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509

from signchain.scanners.base import BaseScanner, extract_certificate_metadata
from signchain.classifiers.crypto_classifier import CryptoClassifier
from signchain.risk.risk_engine import QuantumRiskEngine

MAX_CONTAINER_FILE_SIZE_BYTES = 20 * 1024 * 1024  # 20 MB limit for static analysis safety
SUPPORTED_CONTAINER_EXTENSIONS = {
    ".oci.json",
    ".docker.json",
    ".manifest.json",
    ".container.json",
}

# Standard OCI & Docker Manifest Media Types
OCI_MANIFEST_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}

# Cosign Media Types & Annotations
COSIGN_LAYER_MEDIA_TYPE = "application/vnd.dev.cosign.simplesigning.v1+json"
COSIGN_SIG_ANNOTATION = "dev.cosignproject.cosign/signature"
COSIGN_CERT_ANNOTATION = "dev.cosignproject.cosign/certificate"
COSIGN_CHAIN_ANNOTATION = "dev.cosignproject.cosign/chain"
COSIGN_BUNDLE_ANNOTATION = "dev.sigstore.cosign/bundle"

# Notary Media Types
NOTARY_SIGNATURE_MEDIA_TYPE = "application/vnd.cncf.notary.signature"


class ContainerScanner(BaseScanner):
    """
    Scanner plugin for statically parsing OCI/Docker container image manifests and signatures.
    Strictly performs static analysis; never runs docker daemon or executes container images.
    """

    def __init__(self, max_file_size: int = MAX_CONTAINER_FILE_SIZE_BYTES):
        self.max_file_size = max_file_size

    def can_handle(self, file_path: str) -> bool:
        """
        Determines whether the given file is an OCI/Docker manifest or container metadata bundle.
        """
        if not file_path or not isinstance(file_path, str):
            return False

        if not os.path.isfile(file_path):
            return False

        lower_path = file_path.lower()
        for ext in SUPPORTED_CONTAINER_EXTENSIONS:
            if lower_path.endswith(ext):
                return True

        if lower_path.endswith(".json"):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    preview = f.read(2048)
                    if any(marker in preview for marker in [
                        "application/vnd.oci.image",
                        "application/vnd.docker.distribution.manifest",
                        "dev.cosignproject.cosign",
                        "application/vnd.cncf.notary",
                        "schemaVersion",
                    ]) and ("layers" in preview or "manifests" in preview or "config" in preview or "signatures" in preview):
                        return True
            except Exception:
                return False

        return False

    def scan(self, file_path: str, verify_online: bool = False) -> Dict[str, Any]:
        """
        Statically parses container image manifests, discovering signatures and extracting certificates.
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
                data = json.load(f)
        except Exception as e:
            return {
                "status": "ERROR",
                "error_message": f"Failed to parse JSON content: {str(e)}",
                "file_path": file_path,
            }

        if not isinstance(data, dict):
            return {
                "status": "ERROR",
                "error_message": "Root of container manifest must be a JSON object.",
                "file_path": file_path,
            }

        # 1. Parse Image Identification & Manifest Metadata
        ident = self._parse_image_identification(data, file_path)

        # 2. Discover Signatures (Cosign, Notary, Embedded)
        sig_info, cert_bytes_list = self._discover_signatures(data)

        # 3. Extract and Classify Signing Certificates
        parsed_certs = []
        for idx, cert_raw in enumerate(cert_bytes_list):
            try:
                if b"BEGIN CERTIFICATE" in cert_raw:
                    cert_obj = x509.load_pem_x509_certificate(cert_raw)
                else:
                    cert_obj = x509.load_der_x509_certificate(cert_raw)
            except Exception:
                continue

            rec = extract_certificate_metadata(
                cert=cert_obj,
                file_path=file_path,
                format_label="Container / Cosign (X.509)",
                index=idx,
                extra_fields={
                    "container_image": ident.get("image_name"),
                    "container_digest": ident.get("digest"),
                    "signing_ecosystem": sig_info.get("ecosystem"),
                },
            )
            parsed_certs.append(rec)

        # 4. Determine Overall Signature Status, Quantum Status & Risk
        is_signed = sig_info.get("status") == "SIGNATURE_PRESENT"
        primary_cert = parsed_certs[0] if parsed_certs else None

        if is_signed and primary_cert:
            quantum_status = primary_cert.get("quantum_status", "UNKNOWN")
            risk_score = primary_cert.get("risk_score", 50.0)
            risk_level = primary_cert.get("risk_level", "MEDIUM")
            canonical_alg = primary_cert.get("canonical_algorithm", "UNKNOWN")
        elif is_signed and not primary_cert:
            quantum_status = "UNKNOWN"
            risk_score = 50.0
            risk_level = "MEDIUM"
            canonical_alg = "UNKNOWN"
        else:
            quantum_status = "NOT_APPLICABLE"
            risk_score = 0.0
            risk_level = "LOW"
            canonical_alg = "NONE"

        scan_time = time.perf_counter() - t_start

        return {
            "status": "SUCCESS",
            "artifact_name": os.path.basename(file_path),
            "file_path": file_path,
            "file_size": file_size,
            "ecosystem": "CONTAINER",
            "artifact": ident,
            "signature": {
                "status": sig_info.get("status", "UNSIGNED"),
                "ecosystem": sig_info.get("ecosystem", "NONE"),
                "signature_type": sig_info.get("type", "NONE"),
                "verification": "VERIFICATION_NOT_PERFORMED",
                "signature_count": len(parsed_certs) if parsed_certs else (1 if is_signed else 0),
            },
            "certificate": primary_cert,
            "certificates": parsed_certs,
            "quantum_status": quantum_status,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "public_key_algorithm": primary_cert.get("public_key_algorithm", "NONE") if primary_cert else "NONE",
            "canonical_algorithm": canonical_alg,
            "scan_time_sec": round(scan_time, 6),
        }

    def normalize_result(self, raw_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Normalizes raw container scan results into standardized SignChain schema items.
        """
        if raw_result.get("status") != "SUCCESS":
            return [{
                "status": "ERROR",
                "file_path": raw_result.get("file_path", "unknown"),
                "error_message": raw_result.get("error_message", "Unknown error during container scan"),
            }]

        certs = raw_result.get("certificates", [])
        if certs:
            return certs

        art = raw_result.get("artifact", {})
        sig = raw_result.get("signature", {})

        return [{
            "status": "SUCCESS",
            "artifact_name": raw_result.get("artifact_name"),
            "file_path": raw_result.get("file_path"),
            "format": f"Container ({art.get('media_type', 'OCI Manifest')})",
            "ecosystem": "CONTAINER",
            "container_image": art.get("image_name"),
            "container_digest": art.get("digest"),
            "signature_status": sig.get("status"),
            "signature_verification": sig.get("verification"),
            "quantum_status": raw_result.get("quantum_status", "NOT_APPLICABLE"),
            "risk_score": raw_result.get("risk_score", 0.0),
            "risk_level": raw_result.get("risk_level", "LOW"),
            "public_key_algorithm": raw_result.get("public_key_algorithm", "NONE"),
            "canonical_algorithm": raw_result.get("canonical_algorithm", "NONE"),
        }]

    def _parse_image_identification(self, data: Dict[str, Any], file_path: str) -> Dict[str, Any]:
        """Extracts registry, repository, tag, digest, architecture, and layer counts from manifest."""
        media_type = data.get("mediaType", "application/vnd.oci.image.manifest.v1+json")
        schema_version = data.get("schemaVersion", 2)

        # Digest extraction: top-level digest or sha256 hash of JSON manifest content
        digest = data.get("digest")
        if not digest:
            with open(file_path, "rb") as f:
                content_bytes = f.read()
            digest = f"sha256:{hashlib.sha256(content_bytes).hexdigest()}"

        # Image name & tag from top-level or annotations
        image_str = data.get("image") or data.get("name") or os.path.basename(file_path)
        tag = data.get("tag")
        registry = "UNKNOWN"
        repository = image_str

        if "/" in image_str:
            parts = image_str.split("/", 1)
            if "." in parts[0] or ":" in parts[0] or parts[0] == "localhost":
                registry = parts[0]
                repository = parts[1]

        if ":" in repository:
            repo_parts = repository.split(":", 1)
            repository = repo_parts[0]
            if not tag:
                tag = repo_parts[1]

        # Annotations
        annotations = data.get("annotations", {})
        if not tag and "org.opencontainers.image.version" in annotations:
            tag = annotations["org.opencontainers.image.version"]

        # Architecture & OS
        arch = data.get("architecture") or data.get("config", {}).get("architecture", "UNKNOWN")
        os_name = data.get("os") or data.get("config", {}).get("os", "UNKNOWN")

        # Layers
        layers = data.get("layers", [])
        layer_digests = [l.get("digest") for l in layers if isinstance(l, dict) and "digest" in l]

        return {
            "type": "OCI_IMAGE",
            "registry": registry,
            "repository": repository,
            "image_name": f"{registry}/{repository}:{tag}" if registry != "UNKNOWN" else f"{repository}:{tag or 'latest'}",
            "tag": tag or "latest",
            "tag_mutability": "MUTABLE",
            "digest": digest,
            "digest_stability": "IMMUTABLE",
            "media_type": media_type,
            "schema_version": schema_version,
            "architecture": arch,
            "os": os_name,
            "layer_count": len(layers),
            "layer_digests": layer_digests[:10],
            "config_digest": data.get("config", {}).get("digest", "UNKNOWN"),
        }

    def _discover_signatures(self, data: Dict[str, Any]) -> Tuple[Dict[str, Any], List[bytes]]:
        """Identifies Cosign, Notary, or embedded signature descriptors and returns cert payloads."""
        cert_bytes_list: List[bytes] = []

        # 1. Cosign Signature in layers or annotations
        layers = data.get("layers", [])
        for layer in layers:
            if not isinstance(layer, dict):
                continue
            media_type = layer.get("mediaType", "")
            ann = layer.get("annotations", {})

            if media_type == COSIGN_LAYER_MEDIA_TYPE or COSIGN_SIG_ANNOTATION in ann:
                # Found Cosign signature layer
                cert_pem = ann.get(COSIGN_CERT_ANNOTATION)
                if cert_pem:
                    cert_bytes_list.append(cert_pem.encode("utf-8") if isinstance(cert_pem, str) else cert_pem)

                chain_pem = ann.get(COSIGN_CHAIN_ANNOTATION)
                if chain_pem:
                    cert_bytes_list.append(chain_pem.encode("utf-8") if isinstance(chain_pem, str) else chain_pem)

                return {
                    "status": "SIGNATURE_PRESENT",
                    "ecosystem": "COSIGN",
                    "type": "COSIGN_LAYER_ANNOTATION",
                }, cert_bytes_list

        # 2. Embedded signatures array in container metadata
        sigs = data.get("signatures", [])
        if sigs:
            for s in sigs:
                if isinstance(s, dict):
                    c_str = s.get("certificate") or s.get("cert")
                    if c_str:
                        cert_bytes_list.append(c_str.encode("utf-8") if isinstance(c_str, str) else c_str)

            eco = sigs[0].get("ecosystem", "COSIGN") if isinstance(sigs[0], dict) else "COSIGN"
            return {
                "status": "SIGNATURE_PRESENT",
                "ecosystem": eco,
                "type": "EMBEDDED_SIGNATURE_LIST",
            }, cert_bytes_list

        # 3. Notary v2 Signature Artifact
        artifact_type = data.get("artifactType", "")
        if artifact_type == NOTARY_SIGNATURE_MEDIA_TYPE or "notary" in str(data.get("mediaType", "")).lower():
            # Check for Notary certs in blobs or annotations
            return {
                "status": "SIGNATURE_PRESENT",
                "ecosystem": "NOTARY_V2",
                "type": "NOTARY_ARTIFACT_DESCRIPTOR",
            }, cert_bytes_list

        # Unsigned
        return {
            "status": "UNSIGNED",
            "ecosystem": "NONE",
            "type": "NONE",
        }, []
