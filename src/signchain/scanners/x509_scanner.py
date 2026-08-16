"""
X.509 Certificate Scanner plugin for SignChain.
"""
import os
import hashlib
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa
from cryptography.exceptions import UnsupportedAlgorithm

from signchain.scanners.base import BaseScanner, extract_certificate_metadata

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB limit per cert file for static analysis safety
SUPPORTED_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".cert"}


class X509Scanner(BaseScanner):
    """
    Scanner plugin for parsing and extracting metadata from X.509 certificates (PEM/DER).
    """

    def can_handle(self, file_path: str) -> bool:
        """
        Check if file is likely an X.509 certificate based on extension or magic headers.
        """
        if not file_path or not isinstance(file_path, str):
            return False

        if not os.path.isfile(file_path):
            return False

        ext = os.path.splitext(file_path)[1].lower()
        if ext in SUPPORTED_EXTENSIONS:
            return True

        # Quick check for PEM magic header or DER binary structure
        try:
            with open(file_path, "rb") as f:
                header = f.read(64)
                if b"-----BEGIN CERTIFICATE-----" in header:
                    return True
                # DER certs typically start with ASN.1 SEQUENCE tag (0x30)
                if len(header) > 2 and header[0] == 0x30 and header[1] in (0x81, 0x82):
                    return True
        except Exception:
            return False

        return False

    def scan(self, file_path: str) -> Dict[str, Any]:
        """
        Scans an X.509 certificate file and extracts cryptographic metadata.
        
        Args:
            file_path: Path to the X.509 certificate artifact.
            
        Returns:
            A raw result dictionary containing certificate fields or error details.
        """
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

        if file_size > MAX_FILE_SIZE_BYTES:
            return {
                "status": "ERROR",
                "error_message": f"File exceeds maximum allowed size ({file_size} > {MAX_FILE_SIZE_BYTES} bytes).",
                "file_path": file_path,
            }

        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except Exception as e:
            return {
                "status": "ERROR",
                "error_message": f"Failed to read file: {str(e)}",
                "file_path": file_path,
            }

        certs: List[x509.Certificate] = []
        encoding_format = "PEM"

        # Attempt loading as PEM
        if b"-----BEGIN CERTIFICATE-----" in data:
            try:
                certs = x509.load_pem_x509_certificates(data)
            except Exception as e:
                return {
                    "status": "ERROR",
                    "error_message": f"Malformed PEM certificate data: {str(e)}",
                    "file_path": file_path,
                }
        else:
            # Attempt loading as DER
            encoding_format = "DER"
            try:
                cert = x509.load_der_x509_certificate(data)
                certs = [cert]
            except Exception as der_err:
                return {
                    "status": "ERROR",
                    "error_message": f"Failed to parse X.509 certificate as PEM or DER: {str(der_err)}",
                    "file_path": file_path,
                }

        if not certs:
            return {
                "status": "ERROR",
                "error_message": "No valid X.509 certificates found in file.",
                "file_path": file_path,
            }

        parsed_records = []
        for index, cert in enumerate(certs):
            record = extract_certificate_metadata(
                cert=cert,
                file_path=file_path,
                format_label=f"X.509 ({encoding_format})",
                index=index,
            )
            parsed_records.append(record)

        return {
            "status": "SUCCESS",
            "file_path": file_path,
            "certificate_count": len(parsed_records),
            "certificates": parsed_records,
        }

    def normalize_result(self, raw_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Normalizes raw scanner dictionary into standard SignChain output format.
        """
        if raw_result.get("status") != "SUCCESS":
            return [{
                "status": "ERROR",
                "file_path": raw_result.get("file_path", "unknown"),
                "error_message": raw_result.get("error_message", "Unknown error during scan"),
            }]

        return raw_result.get("certificates", [])

