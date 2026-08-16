"""
Sigstore synthetic test fixture generators for testing bundle parsing, Fulcio identity, and Rekor extraction.
"""
import json
import base64
import datetime
from typing import Dict, Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding


def generate_fulcio_certificate(
    key_type: str = "ECDSA",
    san_email: Optional[str] = "developer@example.com",
    san_uri: Optional[str] = "https://github.com/signchain/core/.github/workflows/build.yml@refs/heads/main",
    oidc_issuer: str = "https://token.actions.githubusercontent.com",
    github_repo: str = "signchain/core",
) -> bytes:
    """Generates a synthetic Fulcio-style X.509 certificate (DER bytes) with SAN and OIDC custom extensions."""
    if key_type == "RSA":
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    else:
        priv = ec.generate_private_key(ec.SECP256R1())

    pub = priv.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([]))
    builder = builder.issuer_name(
        x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "sigstore-fulcio-ca")])
    )
    builder = builder.public_key(pub)
    builder = builder.serial_number(987654321)
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = builder.not_valid_before(now - datetime.timedelta(minutes=1))
    builder = builder.not_valid_after(now + datetime.timedelta(minutes=10))

    # Add SAN Email or URI
    san_list = []
    if san_email:
        san_list.append(x509.RFC822Name(san_email))
    if san_uri:
        san_list.append(x509.UniformResourceIdentifier(san_uri))
    if san_list:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_list), critical=False)

    # Add custom Fulcio OIDC extensions
    if oidc_issuer:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.1"), oidc_issuer.encode("utf-8")),
            critical=False,
        )
    if github_repo:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.5"), github_repo.encode("utf-8")),
            critical=False,
        )

    cert = builder.sign(priv, hashes.SHA256())
    return cert.public_bytes(Encoding.DER)


def generate_sigstore_v03_bundle(
    key_type: str = "ECDSA",
    san_email: Optional[str] = "ci-bot@signchain.org",
    san_uri: Optional[str] = "https://github.com/signchain/release/.github/workflows/deploy.yml@refs/heads/v1",
    include_tlog: bool = True,
    artifact_hash: str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
) -> Dict[str, Any]:
    """Generates a synthetic Sigstore v0.3 Bundle dictionary."""
    cert_der = generate_fulcio_certificate(key_type=key_type, san_email=san_email, san_uri=san_uri)
    cert_b64 = base64.b64encode(cert_der).decode("ascii")

    bundle: Dict[str, Any] = {
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
        "verificationMaterial": {
            "x509CertificateChain": {
                "certificates": [
                    {"rawBytes": cert_b64}
                ]
            }
        },
        "messageSignature": {
            "messageDigest": {
                "algorithm": "SHA2_256",
                "digest": base64.b64encode(bytes.fromhex(artifact_hash)).decode("ascii"),
            },
            "signature": base64.b64encode(b"\x11" * 64).decode("ascii"),
        },
    }

    if include_tlog:
        bundle["verificationMaterial"]["tlogEntries"] = [
            {
                "logIndex": "19482711",
                "logId": {"keyId": base64.b64encode(b"\x22" * 32).decode("ascii")},
                "integratedTime": "1710000000",
                "inclusionProof": {
                    "logIndex": "19482711",
                    "rootHash": base64.b64encode(b"\x33" * 32).decode("ascii"),
                    "treeSize": "20500100",
                },
            }
        ]

    return bundle


def generate_sigstore_dsse_bundle(
    subject_name: str = "signchain-binary-v1.0.tar.gz",
    subject_sha256: str = "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
) -> Dict[str, Any]:
    """Generates a synthetic Sigstore in-toto DSSE envelope bundle."""
    cert_der = generate_fulcio_certificate(san_email="release@signchain.org", san_uri=None)
    cert_b64 = base64.b64encode(cert_der).decode("ascii")

    intoto_payload = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": subject_name,
                "digest": {"sha256": subject_sha256},
            }
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {"buildType": "https://actions.github.com/v1"}
        },
    }
    payload_b64 = base64.b64encode(json.dumps(intoto_payload).encode("utf-8")).decode("ascii")

    return {
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
        "verificationMaterial": {
            "certificate": {
                "rawBytes": cert_b64
            },
            "tlogEntries": [
                {
                    "logIndex": "25010999",
                    "integratedTime": "1715000000",
                    "inclusionProof": {
                        "logIndex": "25010999",
                        "rootHash": base64.b64encode(b"\x44" * 32).decode("ascii"),
                        "treeSize": "30000000",
                    },
                }
            ],
        },
        "dsseEnvelope": {
            "payload": payload_b64,
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [
                {
                    "keyid": "",
                    "sig": base64.b64encode(b"\x55" * 64).decode("ascii"),
                }
            ],
        },
    }
