"""
ca.py

Creation and loading of the Robobo Root Certificate Authority.
"""

from __future__ import annotations

from datetime import datetime, timedelta, UTC

from cryptography import x509
from cryptography.x509.oid import NameOID

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from pki.models import RootCA
from pki.utils import (
    load_certificate,
    load_private_key,
    save_certificate,
    save_private_key,
    certificate_fingerprint,
    print_header,
    print_info,
    print_success,
    random_serial_number,
)


# =============================================================================
# Public API
# =============================================================================

def load_or_create_root_ca(config, paths, force: bool = False) -> RootCA:
    """
    Loads an existing Root CA, or creates one if it doesn't exist (or if force=True).
    """

    if (
        not force
        and paths.ca_key.exists()
        and paths.ca_certificate.exists()
    ):

        print_header("Loading Root CA")

        key = load_private_key(paths.ca_key)

        certificate = load_certificate(
            paths.ca_certificate
        )

        print_success("Existing Root CA loaded.")

        return RootCA(
            private_key=key,
            certificate=certificate,
            key_path=paths.ca_key,
            certificate_path=paths.ca_certificate,
        )

    print_header("Generating Root CA")

    return create_root_ca(config, paths)


# =============================================================================
# Root CA generation
# =============================================================================

def create_root_ca(config, paths) -> RootCA:

    key = ec.generate_private_key(
        ec.SECP256R1()
    )

    subject = x509.Name([
        x509.NameAttribute(
            NameOID.COUNTRY_NAME,
            config.ca.country,
        ),
        x509.NameAttribute(
            NameOID.ORGANIZATION_NAME,
            config.ca.organization,
        ),
        x509.NameAttribute(
            NameOID.COMMON_NAME,
            config.ca.common_name,
        ),
    ])

    now = datetime.now(UTC)

    certificate = (
        x509.CertificateBuilder()

        .subject_name(subject)

        .issuer_name(subject)

        .public_key(
            key.public_key()
        )

        .serial_number(
            random_serial_number()
        )

        .not_valid_before(now)

        .not_valid_after(
            now + timedelta(days=365 * 20)
        )

        #
        # Extensions
        #

        .add_extension(

            x509.BasicConstraints(
                ca=True,
                path_length=None,
            ),

            critical=True,

        )

        .add_extension(

            x509.KeyUsage(

                digital_signature=True,

                content_commitment=False,

                key_encipherment=False,

                data_encipherment=False,

                key_agreement=False,

                key_cert_sign=True,

                crl_sign=True,

                encipher_only=False,

                decipher_only=False,

            ),

            critical=True,

        )

        .add_extension(

            x509.SubjectKeyIdentifier.from_public_key(
                key.public_key()
            ),

            critical=False,

        )

        .add_extension(

            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                key.public_key()
            ),

            critical=False,

        )

        .sign(

            private_key=key,

            algorithm=hashes.SHA256(),

        )

    )

    save_private_key(
        key,
        paths.ca_key,
    )

    save_certificate(
        certificate,
        paths.ca_certificate,
    )

    print_success("Root CA generated.")

    print_info(
        f"Fingerprint:\n{certificate_fingerprint(certificate)}"
    )

    return RootCA(
        private_key=key,
        certificate=certificate,
        key_path=paths.ca_key,
        certificate_path=paths.ca_certificate,
    )


def verify_root_ca(root_ca: RootCA) -> tuple[bool, str]:
    """
    Cryptographically verifies the Root CA self-signature, key pair match, and validity window.
    """
    now = datetime.now(UTC)
    cert = root_ca.certificate

    try:
        nvb = cert.not_valid_before_utc
        nva = cert.not_valid_after_utc
    except AttributeError:
        nvb = cert.not_valid_before
        nva = cert.not_valid_after

    if now < nvb:
        return False, f"Root CA not yet valid (valid from {nvb})"
    if now > nva:
        return False, f"Root CA expired on {nva}"

    try:
        root_ca.public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )
    except Exception as e:
        return False, f"Root CA self-signature verification failed: {e}"

    return True, "Root CA is valid"

