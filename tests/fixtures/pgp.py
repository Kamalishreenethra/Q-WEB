"""
OpenPGP / PGP synthetic test fixture generators for testing key and signature discovery.
"""
import struct
import hashlib
import time
import base64
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def crc24(data: bytes) -> int:
    """Computes RFC 4880 24-bit Radix-64 checksum."""
    crc = 0xB704CE
    for b in data:
        crc ^= (b << 16)
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def armor_block(tag_name: str, raw_data: bytes, headers: str = "") -> str:
    """Wraps binary packet bytes into RFC 4880 ASCII Armor."""
    b64 = base64.b64encode(raw_data).decode("ascii")
    crc = crc24(raw_data)
    crc_b64 = base64.b64encode(crc.to_bytes(3, "big")).decode("ascii")

    hdr_section = f"{headers}\n" if headers else ""
    out = f"-----BEGIN PGP {tag_name}-----\n{hdr_section}\n"
    for i in range(0, len(b64), 64):
        out += b64[i : i + 64] + "\n"
    out += f"={crc_b64}\n-----END PGP {tag_name}-----\n"
    return out


def pack_new_packet(tag: int, body: bytes) -> bytes:
    """Encodes an RFC 4880 New Format packet header."""
    l = len(body)
    if l < 192:
        hdr = bytes([0xC0 | tag, l])
    elif l < 8384:
        l -= 192
        hdr = bytes([0xC0 | tag, 192 + (l >> 8), l & 0xFF])
    else:
        hdr = bytes([0xC0 | tag, 0xFF]) + struct.pack(">I", l)
    return hdr + body


def pack_mpi(val_bytes: bytes, bit_len: int) -> bytes:
    """Encodes a big-endian multi-precision integer (MPI)."""
    return struct.pack(">H", bit_len) + val_bytes


def generate_pgp_rsa_public_key(
    key_size: int = 2048,
    user_id: str = "Alice Test <alice@example.com>",
) -> Tuple[str, bytes]:
    """Generates an RFC 4880 RSA Public Key packet and User ID packet."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    pub = priv.public_key()
    nums = pub.public_numbers()

    n_bytes = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
    e_bytes = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")

    mpi_n = pack_mpi(n_bytes, nums.n.bit_length())
    mpi_e = pack_mpi(e_bytes, nums.e.bit_length())

    ctime = int(time.time())
    pkt_body = struct.pack(">B I B", 4, ctime, 1) + mpi_n + mpi_e
    key_pkt = pack_new_packet(6, pkt_body)
    uid_pkt = pack_new_packet(13, user_id.encode("utf-8"))

    raw_bytes = key_pkt + uid_pkt
    armored = armor_block("PUBLIC KEY BLOCK", raw_bytes)
    return armored, raw_bytes


def generate_pgp_ecdsa_public_key(
    curve_name: str = "NIST P-256",
    user_id: str = "Bob ECC <bob@example.com>",
) -> Tuple[str, bytes]:
    """Generates an RFC 6637 ECDSA Public Key packet."""
    if curve_name == "NIST P-384":
        curve = ec.SECP384R1()
        oid_bytes = b"\x2b\x81\x04\x00\x22"
    elif curve_name == "NIST P-521":
        curve = ec.SECP521R1()
        oid_bytes = b"\x2b\x81\x04\x00\x23"
    else:
        curve = ec.SECP256R1()
        oid_bytes = b"\x2a\x86\x48\xce\x3d\x03\x01\x07"

    priv = ec.generate_private_key(curve)
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.UncompressedPoint,
    )

    mpi_q = pack_mpi(pub_bytes, len(pub_bytes) * 8)
    oid_field = bytes([len(oid_bytes)]) + oid_bytes
    kdf_field = b"\x03\x01\x08\x07"  # KDF params: len 3, hash sha256, sym aes128

    ctime = int(time.time())
    pkt_body = struct.pack(">B I B", 4, ctime, 19) + oid_field + mpi_q + kdf_field
    key_pkt = pack_new_packet(6, pkt_body)
    uid_pkt = pack_new_packet(13, user_id.encode("utf-8"))

    raw_bytes = key_pkt + uid_pkt
    armored = armor_block("PUBLIC KEY BLOCK", raw_bytes)
    return armored, raw_bytes


def generate_pgp_detached_signature(
    issuer_key_id_hex: str = "A50FA65CB89290FB",
    pk_alg_id: int = 1,  # RSA
    hash_alg_id: int = 8,  # SHA-256
) -> Tuple[str, bytes]:
    """Generates an RFC 4880 Detached Signature Packet (Tag 2)."""
    now = int(time.time())
    subpkt_creation = struct.pack(">B B I", 5, 2, now)
    subpkt_issuer = struct.pack(">B B 8s", 9, 16, bytes.fromhex(issuer_key_id_hex[:16]))

    hashed_subpkts = subpkt_creation + subpkt_issuer
    hashed_len = len(hashed_subpkts)
    unhashed_len = 0
    hash_prefix = b"\xAB\xCD"

    # Synthetic signature MPI
    dummy_sig = b"\x55" * 256
    mpi_sig = struct.pack(">H", 2048) + dummy_sig

    sig_body = (
        struct.pack(">B B B B H", 4, 0, pk_alg_id, hash_alg_id, hashed_len)
        + hashed_subpkts
        + struct.pack(">H", unhashed_len)
        + hash_prefix
        + mpi_sig
    )

    sig_pkt = pack_new_packet(2, sig_body)
    armored = armor_block("SIGNATURE", sig_pkt)
    return armored, sig_pkt


def generate_pgp_signed_message(
    message: str = "Release artifact hash payload verification data.",
    issuer_key_id_hex: str = "A50FA65CB89290FB",
) -> str:
    """Generates a Cleartext Signed Message block."""
    sig_armored, _ = generate_pgp_detached_signature(issuer_key_id_hex=issuer_key_id_hex)
    return (
        "-----BEGIN PGP SIGNED MESSAGE-----\n"
        "Hash: SHA256\n\n"
        f"{message}\n"
        f"{sig_armored}"
    )
