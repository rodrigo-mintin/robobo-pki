"""
certificates.py

Generation and loading of robot certificates.
"""

from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import (
    NameOID,
    ExtendedKeyUsageOID,
)


from pki.ca import RootCA
from pki.config import FleetConfig
from pki.models import (
    ProjectPaths,
    RobotCertificate,
    RobotIdentity,
)
from pki.naming import (
    alias,
    certificate_path,
    hostname,
    key_path,
)
from pki.utils import (
    load_certificate,
    load_private_key,
    print_info,
    print_success,
    save_certificate,
    save_private_key,
)


# =============================================================================
# Public API
# =============================================================================


def load_or_create_robot_certificate(
    robot: RobotIdentity,
    root_ca: RootCA,
    config: FleetConfig,
    paths: ProjectPaths,
    force: bool = False,
) -> RobotCertificate:
    """
    Loads an existing robot certificate or creates one.

    Certificates are not regenerated if both the key and the certificate
    already exist, unless force=True.
    """

    key_file = key_path(
        robot,
        config.server,
        paths,
    )

    certificate_file = certificate_path(
        robot,
        config.server,
        paths,
    )

    if not force and key_file.exists() and certificate_file.exists():

        return _load_robot_certificate(
            robot,
            key_file,
            certificate_file,
        )

    return _create_robot_certificate(
        robot,
        root_ca,
        config,
        paths,
    )


# =============================================================================
# Loading
# =============================================================================


def _load_robot_certificate(
    robot: RobotIdentity,
    key_file: Path,
    certificate_file: Path,
) -> RobotCertificate:

    print_info(f"Loading {robot.id}")

    private_key = load_private_key(key_file)

    certificate = load_certificate(certificate_file)

    return RobotCertificate(
        robot=robot,
        private_key=private_key,
        certificate=certificate,
        key_path=key_file,
        certificate_path=certificate_file,
    )


# =============================================================================
# Creation
# =============================================================================


def _create_robot_certificate(
    robot: RobotIdentity,
    root_ca: RootCA,
    config: FleetConfig,
    paths: ProjectPaths,
) -> RobotCertificate:

    print_info(f"Generating {robot.id}")

    key_file = key_path(
        robot,
        config.server,
        paths,
    )

    certificate_file = certificate_path(
        robot,
        config.server,
        paths,
    )

    private_key = _generate_key()

    builder = _build_certificate(
        robot=robot,
        root_ca=root_ca,
        private_key=private_key,
        config=config,
    )

    #
    # Actual signing is performed by the Root CA.
    #
    certificate = root_ca.sign(builder)

    _save(
        private_key,
        certificate,
        key_file,
        certificate_file,
    )

    print_success(f"Generated {robot.id}")

    return RobotCertificate(
        robot=robot,
        private_key=private_key,
        certificate=certificate,
        key_path=key_file,
        certificate_path=certificate_file,
    )


# =============================================================================
# Key generation
# =============================================================================


def _generate_key() -> ec.EllipticCurvePrivateKey:
    """
    Generates a new EC private key.
    """

    return ec.generate_private_key(
        ec.SECP256R1()
    )


# =============================================================================
# Saving
# =============================================================================


def _save(
    private_key: ec.EllipticCurvePrivateKey,
    certificate: x509.Certificate,
    key_file: Path,
    certificate_file: Path,
) -> None:

    save_private_key(
        private_key,
        key_file,
    )

    save_certificate(
        certificate,
        certificate_file,
    )


# =============================================================================
# Certificate builder
# =============================================================================


def _build_certificate(
    robot: RobotIdentity,
    root_ca: RootCA,
    private_key: ec.EllipticCurvePrivateKey,
    config: FleetConfig,
) -> x509.CertificateBuilder:
    """
    Builds (but does not sign) a robot certificate.
    """

    now = datetime.now(timezone.utc)

    robot_hostname = hostname(
        robot,
        config.server,
    )

    subject = x509.Name([
        x509.NameAttribute(
            NameOID.COMMON_NAME,
            robot_hostname,
        ),
    ])

    builder = (
        x509.CertificateBuilder()

        #
        # Subject / Issuer
        #
        .subject_name(subject)
        .issuer_name(root_ca.subject)

        #
        # Key
        #
        .public_key(
            private_key.public_key()
        )

        #
        # Validity
        #
        .serial_number(
            root_ca.next_serial_number()
        )

        .not_valid_before(now)

        .not_valid_after(
            now + timedelta(
                days=365 * config.certificates.validity_years
            )
        )

        #
        # Extensions
        #

        #
        # This is NOT a CA
        #
        .add_extension(
            x509.BasicConstraints(
                ca=False,
                path_length=None,
            ),
            critical=True,
        )

        #
        # Key Usage (EC / ECDSA compliant)
        #
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

        #
        # Server Authentication
        #
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=False,
        )

        #
        # Subject Key Identifier
        #
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                private_key.public_key()
            ),
            critical=False,
        )

        #
        # Authority Key Identifier
        #
        .add_extension(
            root_ca.authority_key_identifier(),
            critical=False,
        )

        #
        # Subject Alternative Names (full hostname + short hostname)
        #
        san_dns = [x509.DNSName(robot_hostname)]
        if robot_hostname.endswith(".local"):
            san_dns.append(x509.DNSName(robot_hostname[:-6]))

        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_dns),
            critical=False,
        )
    )

    return builder


def verify_robot_certificate(
    robot_cert: RobotCertificate,
    root_ca: RootCA,
) -> tuple[bool, str]:
    """
    Cryptographically verifies that a robot certificate was signed by the Root CA,
    matches its private key, and is within its validity window.
    """
    now = datetime.now(timezone.utc)
    cert = robot_cert.certificate

    try:
        nvb = cert.not_valid_before_utc
        nva = cert.not_valid_after_utc
    except AttributeError:
        nvb = cert.not_valid_before
        nva = cert.not_valid_after

    if now < nvb:
        return False, f"Certificate not yet valid (valid from {nvb})"
    if now > nva:
        return False, f"Certificate expired on {nva}"

    cert_pub_bytes = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_pub_bytes = robot_cert.private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if cert_pub_bytes != key_pub_bytes:
        return False, "Private key does not match certificate public key"

    try:
        root_ca.public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )
    except Exception as e:
        return False, f"Signature verification against Root CA failed: {e}"

    return True, "Certificate is valid and verified against Root CA"


def days_until_expiration(cert: x509.Certificate) -> int:
    """
    Returns the number of days until the certificate expires.
    Returns a negative integer if already expired.
    """
    now = datetime.now(timezone.utc)
    try:
        nva = cert.not_valid_after_utc
    except AttributeError:
        nva = cert.not_valid_after

    return (nva - now).days