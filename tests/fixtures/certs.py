"""
Utility functions to programmatically generate test X.509 certificates (PEM and DER)
for unit test verification using cryptography library.
"""
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519


def generate_rsa_certificate(key_size: int = 2048, is_ca: bool = False) -> tuple[bytes, bytes]:
    """
    Generates a self-signed RSA X.509 certificate.
    Returns tuple of (pem_bytes, der_bytes).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SignChain Test Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"Test RSA-{key_size} Cert"),
    ])

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    builder = builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=is_ca, path_length=None),
        critical=True,
    )

    certificate = builder.sign(private_key, hashes.SHA256())
    pem_bytes = certificate.public_bytes(serialization.Encoding.PEM)
    der_bytes = certificate.public_bytes(serialization.Encoding.DER)

    return pem_bytes, der_bytes


def generate_ecdsa_certificate(curve=ec.SECP256R1()) -> tuple[bytes, bytes]:
    """
    Generates a self-signed ECDSA X.509 certificate.
    Returns tuple of (pem_bytes, der_bytes).
    """
    private_key = ec.generate_private_key(curve)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SignChain Test Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"Test ECDSA-{curve.name} Cert"),
    ])

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    builder = builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )

    certificate = builder.sign(private_key, hashes.SHA256())
    pem_bytes = certificate.public_bytes(serialization.Encoding.PEM)
    der_bytes = certificate.public_bytes(serialization.Encoding.DER)

    return pem_bytes, der_bytes


def generate_ed25519_certificate() -> tuple[bytes, bytes]:
    """
    Generates a self-signed Ed25519 X.509 certificate.
    Returns tuple of (pem_bytes, der_bytes).
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test Ed25519 Cert"),
    ])

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    builder = builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=90))

    certificate = builder.sign(private_key, algorithm=None)
    pem_bytes = certificate.public_bytes(serialization.Encoding.PEM)
    der_bytes = certificate.public_bytes(serialization.Encoding.DER)

    return pem_bytes, der_bytes
