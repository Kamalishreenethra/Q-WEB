"""
Utility functions to programmatically generate test Windows PE executables (signed and unsigned)
for unit testing Authenticode signature discovery and extraction.
"""
import struct
from typing import List, Optional
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7, Encoding
from tests.fixtures.certs import generate_rsa_certificate, generate_ecdsa_certificate


def generate_unsigned_pe_file(is_64bit: bool = True) -> bytes:
    """
    Generates a valid synthetic unsigned PE executable (PE32 or PE32+).
    """
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 64)  # e_lfanew = 64

    pe_sig = b"PE\x00\x00"

    machine = 0x8664 if is_64bit else 0x014C
    opt_magic = 0x020B if is_64bit else 0x010B
    opt_size = 240 if is_64bit else 224

    coff = struct.pack(
        "<HHIIIHH",
        machine,
        1,       # NumberOfSections
        0,       # TimeDateStamp
        0,       # PointerToSymbolTable
        0,       # NumberOfSymbols
        opt_size,
        0x0022,  # Characteristics
    )

    if is_64bit:
        opt_std = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            opt_magic,
            14, 0,
            512, 0, 0,
            0x1000, 0x1000,
            0x140000000,
            0x1000, 0x200,
            6, 0, 0, 0, 6, 0, 0,
            0x2000, 0x200,
            0, 3, 0x8160,
            0x100000, 0x1000,
            0x100000, 0x1000,
            0, 16
        )
    else:
        opt_std = struct.pack(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
            opt_magic,
            14, 0,
            512, 0, 0,
            0x1000, 0x1000, 0x2000,
            0x400000,
            0x1000, 0x200,
            6, 0, 0, 0, 6, 0, 0,
            0x2000, 0x200,
            0, 3, 0x8160,
            0x100000, 0x1000,
            0x100000, 0x1000,
            0, 16
        )

    data_dirs = bytearray(16 * 8)  # All zero directories (UNSIGNED)

    sec_hdr = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x100, 0x1000, 0x200, 0x200,
        0, 0, 0, 0,
        0x60000020
    )

    header = dos_header + pe_sig + coff + opt_std + data_dirs + sec_hdr
    header += b"\x00" * (0x200 - len(header))
    sec_data = b"\x90" * 0x200

    return header + sec_data


def generate_signed_pe_file(
    cert_der_bytes_list: Optional[List[bytes]] = None,
    is_64bit: bool = True,
) -> bytes:
    """
    Generates a valid synthetic PE executable with an embedded Authenticode WIN_CERTIFICATE table
    containing serialized PKCS#7 X.509 certificate(s).
    """
    if cert_der_bytes_list is None:
        _, der_data = generate_rsa_certificate(2048)
        cert_der_bytes_list = [der_data]

    certs = [x509.load_der_x509_certificate(b) for b in cert_der_bytes_list]
    p7_bytes = pkcs7.serialize_certificates(certs, Encoding.DER)

    # WIN_CERTIFICATE structure: dwLength (4 bytes), wRevision (2 bytes), wCertificateType (2 bytes) + bCertificate
    win_cert = struct.pack("<IHH", len(p7_bytes) + 8, 0x0200, 0x0002) + p7_bytes
    if len(win_cert) % 8 != 0:
        win_cert += b"\x00" * (8 - (len(win_cert) % 8))

    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 64)

    pe_sig = b"PE\x00\x00"
    machine = 0x8664 if is_64bit else 0x014C
    opt_magic = 0x020B if is_64bit else 0x010B
    opt_size = 240 if is_64bit else 224

    coff = struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, opt_size, 0x0022)

    if is_64bit:
        opt_std = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            opt_magic, 14, 0, 512, 0, 0, 0x1000, 0x1000, 0x140000000, 0x1000, 0x200,
            6, 0, 0, 0, 6, 0, 0, 0x2000, 0x200, 0, 3, 0x8160,
            0x100000, 0x1000, 0x100000, 0x1000, 0, 16
        )
    else:
        opt_std = struct.pack(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
            opt_magic, 14, 0, 512, 0, 0, 0x1000, 0x1000, 0x2000, 0x400000, 0x1000, 0x200,
            6, 0, 0, 0, 6, 0, 0, 0x2000, 0x200, 0, 3, 0x8160,
            0x100000, 0x1000, 0x100000, 0x1000, 0, 16
        )

    data_dirs = bytearray(16 * 8)
    security_offset = 0x400
    security_size = len(win_cert)
    struct.pack_into("<II", data_dirs, 4 * 8, security_offset, security_size)

    sec_hdr = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x100, 0x1000, 0x200, 0x200,
        0, 0, 0, 0,
        0x60000020
    )

    header = dos_header + pe_sig + coff + opt_std + data_dirs + sec_hdr
    header += b"\x00" * (0x200 - len(header))
    sec_data = b"\x90" * 0x200

    return header + sec_data + win_cert
