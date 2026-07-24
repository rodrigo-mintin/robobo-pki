"""
utils.py

Shared helper functions for the Robobo PKI project.
"""

from __future__ import annotations

import os
import secrets
import stat
from hashlib import sha256
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


# ============================================================================
# Filesystem
# ============================================================================

def ensure_parent(path: Path) -> None:
    """
    Creates the parent directory if necessary.
    """

    path.parent.mkdir(parents=True, exist_ok=True)


def ensure_directory(path: Path) -> None:
    """
    Creates the directory if necessary.
    """

    path.mkdir(parents=True, exist_ok=True)


def set_secure_permissions(path: Path) -> None:
    """
    Restricts file permissions to 0600 (owner read/write only) on POSIX systems.
    """

    if os.name != "nt" and path.exists():
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


# ============================================================================
# Private Keys
# ============================================================================

def save_private_key(
    private_key: ec.EllipticCurvePrivateKey,
    path: Path,
) -> None:
    """
    Saves an EC private key in PEM PKCS#8 format with secure permissions.
    """

    ensure_parent(path)

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    path.write_bytes(pem)
    set_secure_permissions(path)


def load_private_key(
    path: Path,
) -> ec.EllipticCurvePrivateKey:
    """
    Loads an EC private key.
    """

    return serialization.load_pem_private_key(
        path.read_bytes(),
        password=None,
    )


# ============================================================================
# Certificates
# ============================================================================

def save_certificate(
    certificate: x509.Certificate,
    path: Path,
) -> None:
    """
    Saves an X509 certificate in PEM format.
    """

    ensure_parent(path)

    path.write_bytes(
        certificate.public_bytes(
            serialization.Encoding.PEM
        )
    )


def load_certificate(
    path: Path,
) -> x509.Certificate:
    """
    Loads an X509 certificate.
    """

    return x509.load_pem_x509_certificate(
        path.read_bytes()
    )


# ============================================================================
# Fingerprints
# ============================================================================

def certificate_fingerprint(
    certificate: x509.Certificate,
) -> str:
    """
    Returns a printable SHA256 fingerprint.

    Example

    AA:14:8B:...
    """

    digest = sha256(
        certificate.public_bytes(
            serialization.Encoding.DER
        )
    ).hexdigest().upper()

    return ":".join(
        digest[i:i + 2]
        for i in range(0, len(digest), 2)
    )


# ============================================================================
# Logging
# ============================================================================

def print_header(title: str) -> None:

    print()
    print("=" * 70)
    print(title)
    print("=" * 70)


def print_success(message: str) -> None:
    try:
        print(f"✓ {message}")
    except UnicodeEncodeError:
        print(f"[OK] {message}")


def print_warning(message: str) -> None:

    print(f"! {message}")


def print_info(message: str) -> None:

    print(f"> {message}")

def random_serial_number() -> int:
    """
    Generates a positive RFC 5280-compliant serial number.

    RFC 5280 limits serial numbers to 20 octets (160 bits). We generate
    a random 159-bit integer to ensure it is always positive.
    """
    return secrets.randbits(159)