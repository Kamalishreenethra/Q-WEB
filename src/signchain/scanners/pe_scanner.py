"""
PE / Authenticode Signature Scanner plugin for SignChain.
Performs safe static analysis of Windows PE binaries (.exe, .dll, .sys, etc.)
and extracts embedded Authenticode PKCS#7 certificate chains.
"""
import os
import struct
import time
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

import pefile
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa
from cryptography.hazmat.primitives.serialization import pkcs7

from signchain.scanners.base import BaseScanner, extract_certificate_metadata

MAX_PE_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB limit for static analysis safety
SUPPORTED_PE_EXTENSIONS = {".exe", ".dll", ".sys", ".ocx", ".efi", ".scr", ".cpl"}

# WIN_CERTIFICATE constants
WIN_CERT_REVISION_1_0 = 0x0100
WIN_CERT_REVISION_2_0 = 0x0200
WIN_CERT_TYPE_X509 = 0x0001
WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002
WIN_CERT_TYPE_RESERVED_1 = 0x0003
WIN_CERT_TYPE_TS_STACK_SIGNED = 0x0004


class PEScanner(BaseScanner):
    """
    Scanner plugin for parsing Windows PE executables and extracting Authenticode code-signing signatures.
    Strictly performs safe static analysis without executing target binaries.
    """

    def __init__(self, max_file_size: int = MAX_PE_FILE_SIZE_BYTES):
        self.max_file_size = max_file_size

    def can_handle(self, file_path: str) -> bool:
        """
        Determines whether this scanner can handle the file based on extension or DOS MZ header.
        """
        if not file_path or not isinstance(file_path, str):
            return False

        if not os.path.isfile(file_path):
            return False

        ext = os.path.splitext(file_path)[1].lower()
        if ext in SUPPORTED_PE_EXTENSIONS:
            return True

        # Fallback: check for DOS 'MZ' header
        try:
            with open(file_path, "rb") as f:
                header = f.read(2)
                if header == b"MZ":
                    return True
        except Exception:
            return False

        return False

    def scan(self, file_path: str) -> Dict[str, Any]:
        """
        Statically analyzes a Windows PE file and extracts Authenticode signature metadata.
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
                data = f.read()
        except Exception as e:
            return {
                "status": "ERROR",
                "error_message": f"Failed to read file: {str(e)}",
                "file_path": file_path,
            }

        # 1. Parse PE Headers using pefile (safe static parsing)
        try:
            pe = pefile.PE(data=data, fast_load=False)
        except pefile.PEFormatError as e:
            return {
                "status": "ERROR",
                "error_message": f"Malformed or invalid PE file: {str(e)}",
                "file_path": file_path,
            }
        except Exception as e:
            return {
                "status": "ERROR",
                "error_message": f"Unexpected error parsing PE structure: {str(e)}",
                "file_path": file_path,
            }

        # Architecture and Format
        machine = pe.FILE_HEADER.Machine
        arch = self._get_machine_architecture(machine)
        pe_format = self._get_pe_format(pe.OPTIONAL_HEADER.Magic)
        subsystem = self._get_subsystem(getattr(pe.OPTIONAL_HEADER, "Subsystem", 0))

        # 2. Check for Security Directory (Authenticode table)
        security_dir = None
        if hasattr(pe, "OPTIONAL_HEADER") and hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
            if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]:
                security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]

        # Handle UNSIGNED PE file
        if not security_dir or security_dir.VirtualAddress == 0 or security_dir.Size == 0:
            scan_time = time.perf_counter() - t_start
            return {
                "status": "SUCCESS",
                "artifact_name": os.path.basename(file_path),
                "file_path": file_path,
                "file_size": file_size,
                "pe_format": pe_format,
                "architecture": arch,
                "subsystem": subsystem,
                "authenticode_status": "UNSIGNED",
                "signature_verification": "NOT_APPLICABLE",
                "certificate_count": 0,
                "certificates": [],
                "scan_time_sec": round(scan_time, 6),
            }

        # 3. Extract and Parse WIN_CERTIFICATE table
        cert_offset = security_dir.VirtualAddress
        cert_size = security_dir.Size

        if cert_offset + cert_size > len(data) or cert_size < 8:
            return {
                "status": "ERROR",
                "error_message": f"Corrupted Authenticode security directory: offset {cert_offset} + size {cert_size} exceeds file length {len(data)}.",
                "file_path": file_path,
                "authenticode_status": "SIGNATURE_PARSE_ERROR",
            }

        raw_win_cert = data[cert_offset : cert_offset + cert_size]
        try:
            dw_length, w_revision, w_cert_type = struct.unpack("<IHH", raw_win_cert[:8])
        except Exception as e:
            return {
                "status": "ERROR",
                "error_message": f"Malformed WIN_CERTIFICATE header: {str(e)}",
                "file_path": file_path,
                "authenticode_status": "SIGNATURE_PARSE_ERROR",
            }

        rev_name = "WIN_CERT_REVISION_2_0" if w_revision == WIN_CERT_REVISION_2_0 else ("WIN_CERT_REVISION_1_0" if w_revision == WIN_CERT_REVISION_1_0 else hex(w_revision))
        cert_type_name = "PKCS_SIGNED_DATA" if w_cert_type == WIN_CERT_TYPE_PKCS_SIGNED_DATA else hex(w_cert_type)

        if w_cert_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA:
            return {
                "status": "ERROR",
                "error_message": f"Unsupported Authenticode certificate type: {cert_type_name} (expected PKCS#7 signed data).",
                "file_path": file_path,
                "authenticode_status": "SIGNATURE_PARSE_ERROR",
            }

        p7_payload = bytes(raw_win_cert[8:dw_length])
        try:
            extracted_certs = pkcs7.load_der_pkcs7_certificates(p7_payload)
        except Exception as e:
            return {
                "status": "ERROR",
                "error_message": f"Failed to parse PKCS#7 Authenticode signature structure: {str(e)}",
                "file_path": file_path,
                "authenticode_status": "SIGNATURE_PARSE_ERROR",
            }

        if not extracted_certs:
            return {
                "status": "ERROR",
                "error_message": "Authenticode table is present but contains no X.509 certificates.",
                "file_path": file_path,
                "authenticode_status": "SIGNATURE_PARSE_ERROR",
            }

        # 4. Normalize and Classify Extracted Certificates
        parsed_records = []
        for index, cert in enumerate(extracted_certs):
            record = extract_certificate_metadata(
                cert=cert,
                file_path=file_path,
                format_label=f"PE / Authenticode ({pe_format})",
                index=index,
                extra_fields={
                    "pe_architecture": arch,
                    "pe_subsystem": subsystem,
                    "authenticode_status": "SIGNED",
                    "authenticode_revision": rev_name,
                },
            )
            parsed_records.append(record)

        scan_time = time.perf_counter() - t_start

        return {
            "status": "SUCCESS",
            "artifact_name": os.path.basename(file_path),
            "file_path": file_path,
            "file_size": file_size,
            "pe_format": pe_format,
            "architecture": arch,
            "subsystem": subsystem,
            "authenticode_status": "SIGNED",
            "authenticode_revision": rev_name,
            "signature_verification": "SIGNATURE_DETECTED_VERIFICATION_NOT_IMPLEMENTED",
            "certificate_count": len(parsed_records),
            "certificates": parsed_records,
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
                "error_message": raw_result.get("error_message", "Unknown error during PE scan"),
                "authenticode_status": raw_result.get("authenticode_status", "SIGNATURE_PARSE_ERROR"),
            }]

        if raw_result.get("authenticode_status") == "UNSIGNED":
            return [{
                "status": "SUCCESS",
                "artifact_name": raw_result.get("artifact_name"),
                "file_path": raw_result.get("file_path"),
                "format": f"PE ({raw_result.get('pe_format', 'PE32+')})",
                "architecture": raw_result.get("architecture"),
                "authenticode_status": "UNSIGNED",
                "signature_status": "UNSIGNED",
                "quantum_status": "NOT_APPLICABLE",
                "quantum_reason": "Artifact is unsigned (no digital signature present).",
                "risk_score": 0.0,
                "risk_level": "LOW",
                "public_key_algorithm": "NONE",
                "canonical_algorithm": "NONE",
                "algorithm_family": "NONE",
                "is_ca": False,
            }]

        return raw_result.get("certificates", [])

    @staticmethod
    def _get_machine_architecture(machine_code: int) -> str:
        """Translates PE machine constants to human-readable architecture strings."""
        if machine_code == 0x014C:
            return "x86 (32-bit)"
        elif machine_code == 0x8664:
            return "x86-64 (64-bit)"
        elif machine_code == 0xAA64:
            return "ARM64"
        elif machine_code == 0x01C0:
            return "ARM (32-bit)"
        elif machine_code == 0x0200:
            return "Intel Itanium (IA-64)"
        return f"Unknown Architecture ({hex(machine_code)})"

    @staticmethod
    def _get_pe_format(magic_code: int) -> str:
        """Translates PE optional header magic constant to PE32 / PE32+ string."""
        if magic_code == 0x10B:
            return "PE32"
        elif magic_code == 0x20B:
            return "PE32+"
        elif magic_code == 0x107:
            return "ROM Image"
        return f"Unknown Format ({hex(magic_code)})"

    @staticmethod
    def _get_subsystem(subsystem_code: int) -> str:
        """Translates PE subsystem constants to readable subsystem string."""
        subsystems = {
            1: "Native",
            2: "Windows GUI",
            3: "Windows CUI (Console)",
            7: "POSIX CUI",
            9: "Windows CE GUI",
            10: "EFI Application",
            11: "EFI Boot Service Driver",
            12: "EFI Runtime Driver",
            13: "EFI ROM",
            14: "XBOX",
        }
        return subsystems.get(subsystem_code, f"Subsystem-{subsystem_code}")

