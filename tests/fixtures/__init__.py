"""Test fixtures and mock certificates for SignChain test suite."""
from tests.fixtures.certs import (
    generate_rsa_certificate,
    generate_ecdsa_certificate,
    generate_ed25519_certificate,
)
from tests.fixtures.pe import (
    generate_unsigned_pe_file,
    generate_signed_pe_file,
)
from tests.fixtures.pgp import (
    generate_pgp_rsa_public_key,
    generate_pgp_ecdsa_public_key,
    generate_pgp_detached_signature,
    generate_pgp_signed_message,
)
from tests.fixtures.sigstore import (
    generate_fulcio_certificate,
    generate_sigstore_v03_bundle,
    generate_sigstore_dsse_bundle,
)
from tests.fixtures.container import (
    generate_container_certificate,
    generate_unsigned_oci_manifest,
    generate_cosign_signed_oci_manifest,
    generate_notary_signed_manifest,
    generate_multiarch_image_index,
)

__all__ = [
    "generate_rsa_certificate",
    "generate_ecdsa_certificate",
    "generate_ed25519_certificate",
    "generate_unsigned_pe_file",
    "generate_signed_pe_file",
    "generate_pgp_rsa_public_key",
    "generate_pgp_ecdsa_public_key",
    "generate_pgp_detached_signature",
    "generate_pgp_signed_message",
    "generate_fulcio_certificate",
    "generate_sigstore_v03_bundle",
    "generate_sigstore_dsse_bundle",
    "generate_container_certificate",
    "generate_unsigned_oci_manifest",
    "generate_cosign_signed_oci_manifest",
    "generate_notary_signed_manifest",
    "generate_multiarch_image_index",
]
