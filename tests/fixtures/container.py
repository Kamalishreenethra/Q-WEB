"""
Container and OCI image manifest synthetic test fixture generators for testing container signing discovery.
"""
import json
import datetime
from typing import Dict, Any, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding


def generate_container_certificate(
    key_type: str = "ECDSA",
    subject_cn: str = "payment-api-signer",
    issuer_cn: str = "container-signing-ca",
) -> str:
    """Generates an X.509 certificate string in PEM format."""
    if key_type == "RSA":
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    else:
        priv = ec.generate_private_key(ec.SECP256R1())

    pub = priv.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(
        x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, subject_cn)])
    )
    builder = builder.issuer_name(
        x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, issuer_cn)])
    )
    builder = builder.public_key(pub)
    builder = builder.serial_number(1122334455)
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = builder.not_valid_before(now - datetime.timedelta(days=1))
    builder = builder.not_valid_after(now + datetime.timedelta(days=365))

    cert = builder.sign(priv, hashes.SHA256())
    return cert.public_bytes(Encoding.PEM).decode("utf-8")


def generate_unsigned_oci_manifest(
    image_name: str = "registry.example.com/payment/api:1.4.2",
    arch: str = "amd64",
    os_name: str = "linux",
) -> Dict[str, Any]:
    """Generates an unsigned standard OCI Image Manifest."""
    return {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "image": image_name,
        "architecture": arch,
        "os": os_name,
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "sha256:d1d2d3d4e5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
            "size": 7023,
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "size": 32654,
            },
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "size": 45120,
            },
        ],
        "annotations": {
            "org.opencontainers.image.title": "payment-api",
            "org.opencontainers.image.version": "1.4.2",
        },
    }


def generate_cosign_signed_oci_manifest(
    key_type: str = "ECDSA",
    image_name: str = "registry.example.com/auth/service:2.0.0",
) -> Dict[str, Any]:
    """Generates an OCI manifest with embedded Cosign signature layer and certificate."""
    cert_pem = generate_container_certificate(key_type=key_type, subject_cn="auth-service-signer")
    return {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "image": image_name,
        "architecture": "amd64",
        "os": "linux",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "sha256:c0ffee0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "size": 4500,
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "size": 12000,
            },
            {
                "mediaType": "application/vnd.dev.cosign.simplesigning.v1+json",
                "digest": "sha256:siglayer1234567890abcdef1234567890abcdef1234567890abcdef12345678",
                "size": 512,
                "annotations": {
                    "dev.cosignproject.cosign/signature": "MEUCIQDx1234567890abcdef...",
                    "dev.cosignproject.cosign/certificate": cert_pem,
                },
            },
        ],
    }


def generate_notary_signed_manifest(
    subject_digest: str = "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
) -> Dict[str, Any]:
    """Generates an OCI Notary v2 signature artifact descriptor."""
    return {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": "application/vnd.cncf.notary.signature",
        "subject": {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": subject_digest,
            "size": 1420,
        },
        "blobs": [
            {
                "mediaType": "application/vnd.cncf.notary.signature.jws",
                "digest": "sha256:99887766554433221100aabbccddeeff99887766554433221100aabbccddeeff",
                "size": 2048,
            }
        ],
    }


def generate_multiarch_image_index() -> Dict[str, Any]:
    """Generates an OCI Image Index containing multi-architecture manifests."""
    return {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "image": "registry.example.com/multi/arch:latest",
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:amd64manifestdigest0123456789abcdef0123456789abcdef0123456789abcdef",
                "size": 7143,
                "platform": {"architecture": "amd64", "os": "linux"},
            },
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:arm64manifestdigest0123456789abcdef0123456789abcdef0123456789abcdef",
                "size": 7143,
                "platform": {"architecture": "arm64", "os": "linux"},
            },
        ],
    }
